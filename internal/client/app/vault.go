package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/cache"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
)

// Item описывает поля минимального представления объекта.
type Item struct {
	ID      string        // ID записи.
	Header  domain.Header // заголовок записи.
	Version int64         // версия записи.
}

// Entry хранит как описание объекта, так и его содержимое.
type Entry struct {
	Item                 // минимальное описание записи.
	Secret domain.Secret // полноценная запись.
	Stale  bool          // данные взяты из кэша без успешной синхронизации с сервером и могут быть устаревшими.
	// Warnings - предупреждения, которые нужно показать пользователю.
	Warnings []string
}

// ListResult представляет из себя список записей без Body.
type ListResult struct {
	Items []Item // список секретов с заголовками.
	Stale bool   // данные взяты из кэша без успешной синхронизации с сервером и могут быть устаревшими.
	// Warnings - предупреждения, которые нужно показать пользователю.
	Warnings []string
}

// ReadOptions задаёт режим чтения.
type ReadOptions struct {
	Offline bool // не обращаться к серверу, читать только кэш; токен может быть просроченным.
	// RequireOnline запрещает подменять недоступный сервер кэшем. Нужен чтению, за которым следует запись.
	RequireOnline bool
}

// AmbiguousError - контейнер ошибок для нерасшифрованных записей.
type AmbiguousError struct {
	Name string   // ID/name нерасшифрованной записи
	IDs  []string // список потенциальных кандидатов на "ту самую" запись.
}

// Error позволяет использовать AmbiguousError как ошибку.
func (a *AmbiguousError) Error() string {
	return fmt.Sprintf("multiple records found for ref %s: %v", a.Name, a.IDs)
}

// Vault - структура, реализующая методы для работы с хранилищем.
type Vault struct {
	srv           VaultServer
	store         session.Store
	openCache     CacheOpener
	serverAddr    string
	bodySizeLimit int
}

// NewVault собирает и возвращает рабочий экземпляр Vault.
func NewVault(srv VaultServer, store session.Store, openCache CacheOpener, serverAddr string, bodySizeLimit int) (*Vault, error) {
	if bodySizeLimit <= 0 {
		return nil, errors.New("size limits should be positive")
	}
	return &Vault{
		srv:           srv,
		store:         store,
		openCache:     openCache,
		serverAddr:    serverAddr,
		bodySizeLimit: bodySizeLimit,
	}, nil
}

// DefaultBodySizeLimit предлагает значение "по умолчанию" предела размера тела.
func DefaultBodySizeLimit() int {
	return 1024 * 1024 // 1 MiB
}

// readState - состояние одной команды чтения: сессия, ключ, открытый кэш и итог синхронизации.
type readState struct {
	sess     session.Session
	sealer   *crypto.Sealer
	cache    Cache
	stale    bool     // синхронизации не было (offline или сеть недоступна)
	warnings []string // предупреждения для пользователя
}

// begin открывает сессию и кэш и синхронизирует кэш с сервером.
// При ro.Offline сервер не опрашивается и срок токена не проверяется.
// Если сервер недоступен на уровне сети, при strict=false возвращается состояние с stale=true,
// при strict=true - ошибка: записи не должны опираться на устаревший кэш.
func (v *Vault) begin(ctx context.Context, ro ReadOptions, strict bool) (*readState, error) {
	strict = strict || ro.RequireOnline
	sess, sealer, err := v.openSession(!ro.Offline)
	if err != nil {
		return nil, fmt.Errorf("error opening session: %w", err)
	}
	c, err := v.openCache(sess.ServerAddr, sess.UserID)
	st := &readState{sess: sess, sealer: sealer, cache: c}
	if err != nil {
		if c == nil {
			return nil, fmt.Errorf("error opening cache: %w", err)
		}
		st.warnings = append(st.warnings, fmt.Sprintf("local cache was reset: %v", err))
	}
	if ro.Offline {
		st.stale = true
		return st, nil
	}
	if err := v.sync(ctx, sess.Token, c); err != nil {
		if errors.Is(err, domain.ErrUnavailable) && !strict {
			st.stale = true
			return st, nil
		}
		return nil, fmt.Errorf("error syncing with server: %w", err)
	}
	return st, nil
}

// sync запрашивает у сервера изменения с последней закэшированной ревизии и применяет их к кэшу.
// Если сервер был сброшен (его ревизия ниже нашей), кэш очищается и изменения запрашиваются с нуля.
func (v *Vault) sync(ctx context.Context, token string, c Cache) error {
	rev, recs, err := v.srv.ListChanges(ctx, token, c.LatestRevision())
	if err != nil {
		return err
	}
	err = c.Apply(rev, recs)
	if errors.Is(err, domain.ErrServerReset) {
		if err := c.Wipe(); err != nil {
			return fmt.Errorf("error wiping cache: %w", err)
		}
		if rev, recs, err = v.srv.ListChanges(ctx, token, 0); err != nil {
			return err
		}
		err = c.Apply(rev, recs)
	}
	if err != nil {
		return fmt.Errorf("error applying changes to cache: %w", err)
	}
	return nil
}

// Add добавляет запись на сервер и в кэш. Предупреждения - это ошибки кэша, которые не мешают результату.
func (v *Vault) Add(ctx context.Context, s domain.Secret) (id string, warnings []string, err error) {
	sess, sealer, err := v.openSession(true)
	if err != nil {
		return "", nil, fmt.Errorf("error opening session: %w", err)
	}
	id = newID()

	body, err := v.seal(sealer, sess.UserID, id, s)
	if err != nil {
		return "", nil, fmt.Errorf("error sealing secret in add: %w", err)
	}

	version, err := v.srv.Put(ctx, sess.Token, id, 0, s.Header, body)
	if err != nil {
		return "", nil, fmt.Errorf("error putting new record on server: %w", err)
	}
	return id, v.writeThrough(sess, func(c Cache) error {
		return c.Put(cache.Entry{ID: id, Version: version, Header: s.Header}, &body)
	}), nil
}

// ListChanges синхронизирует кэш с сервером и возвращает все живые записи без Body. На нём строится sync.
func (v *Vault) ListChanges(ctx context.Context, ro ReadOptions) (ListResult, error) {
	return v.List(ctx, domain.Filter{}, ro)
}

// List синхронизирует кэш с сервером и ищет в нём живые записи по filter. Записи возвращаются без Body.
// Условия объединяются по И; имя ищется как подстрока без учёта регистра, ключ меты - точно.
func (v *Vault) List(ctx context.Context, filter domain.Filter, ro ReadOptions) (ListResult, error) {
	st, err := v.begin(ctx, ro, false)
	if err != nil {
		return ListResult{}, err
	}
	result := ListResult{Items: []Item{}, Stale: st.stale, Warnings: st.warnings}
	fragment := strings.ToLower(filter.NameFragment)
	for _, e := range st.cache.Entries() {
		if filter.Type != "" && e.Header.Type != filter.Type {
			continue
		}
		if fragment != "" && !strings.Contains(strings.ToLower(e.Header.Name), fragment) {
			continue
		}
		if filter.MetaKey != "" && !hasMetaKey(e.Header.Meta, filter.MetaKey) {
			continue
		}
		result.Items = append(result.Items, itemOf(e))
	}
	return result, nil
}

func hasMetaKey(meta []domain.MetaItem, key string) bool {
	for _, m := range meta {
		if m.Key == key {
			return true
		}
	}
	return false
}

func itemOf(e cache.Entry) Item {
	return Item{ID: e.ID, Header: e.Header, Version: e.Version}
}

// Resolve нужен для определения, чем является ref: ID или именем записи.
// Для этого он синхронизирует кэш и ищет соответствие среди закэшированных заголовков.
func (v *Vault) Resolve(ctx context.Context, ref string, ro ReadOptions) (Item, error) {
	st, err := v.begin(ctx, ro, false)
	if err != nil {
		return Item{}, err
	}
	return resolveIn(st.cache, ref)
}

func resolveIn(c Cache, ref string) (Item, error) {
	var candidates []Item
	for _, e := range c.Entries() {
		if e.ID == ref {
			// ID точно побеждает
			return itemOf(e), nil
		}
		if e.Header.Name == ref {
			candidates = append(candidates, itemOf(e))
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0], nil
	case 0:
		return Item{}, domain.ErrNotFound
	default:
		candIDs := make([]string, 0, len(candidates))
		for _, cand := range candidates {
			candIDs = append(candIDs, cand.ID)
		}
		return Item{}, &AmbiguousError{Name: ref, IDs: candIDs}
	}
}

// Get получает и расшифровывает запись целиком. Тело берётся из кэша, если его версия совпадает с версией
// заголовка, иначе скачивается с сервера и кэшируется.
func (v *Vault) Get(ctx context.Context, ref string, ro ReadOptions) (Entry, error) {
	st, err := v.begin(ctx, ro, false)
	if err != nil {
		return Entry{}, err
	}
	item, err := resolveIn(st.cache, ref)
	if err != nil {
		return Entry{}, fmt.Errorf("error resolving record: %w", err)
	}

	sealed, cached, err := st.cache.Body(item.ID, item.Version)
	if err != nil {
		st.warnings = append(st.warnings, fmt.Sprintf("cannot read cached body: %v", err))
	}
	fromCache := cached
	for attempt := 0; ; attempt++ {
		if !cached {
			if st.stale {
				return Entry{}, fmt.Errorf("record %s: %w", item.ID, domain.ErrBodyNotCached)
			}
			record, err := v.srv.Get(ctx, st.sess.Token, item.ID)
			if err != nil {
				if errors.Is(err, domain.ErrUnavailable) {
					return Entry{}, fmt.Errorf("record %s: %w: %w", item.ID, domain.ErrBodyNotCached, err)
				}
				return Entry{}, fmt.Errorf("error getting record body: %w", err)
			}
			item = Item{ID: record.ID, Header: record.Header, Version: record.Version}
			sealed = record.Body
			if err := st.cache.PutBody(item.ID, item.Version, sealed); err != nil {
				st.warnings = append(st.warnings, fmt.Sprintf("local cache was not updated: %v", err))
			}
		}
		bb, err := st.sealer.Open(st.sess.UserID, item.ID, crypto.PartBody, sealed)
		if err != nil {
			if fromCache && attempt == 0 && !st.stale {
				// закэшированное тело испорчено: скачиваем заново
				cached, fromCache = false, false
				continue
			}
			return Entry{}, fmt.Errorf("error opening record body: %w", err)
		}
		sec, err := domain.Unmarshal(item.Header, bb)
		if err != nil {
			return Entry{}, fmt.Errorf("error unmarshalling secret: %w", err)
		}
		return Entry{
			ID: item.ID, Header: sec.Header, Version: item.Version,
			Secret:   sec,
			Stale:    st.stale,
			Warnings: st.warnings,
		}, nil
	}
}

// Update загружает новую версию записи на сервере и в кэше.
func (v *Vault) Update(ctx context.Context, id string, expectedVersion int64, s domain.Secret) (warnings []string, err error) {
	sess, sealer, err := v.openSession(true)
	if err != nil {
		return nil, fmt.Errorf("error opening session: %w", err)
	}

	body, err := v.seal(sealer, sess.UserID, id, s)
	if err != nil {
		return nil, fmt.Errorf("error sealing secret in update: %w", err)
	}

	version, err := v.srv.Put(ctx, sess.Token, id, expectedVersion, s.Header, body)
	if err != nil {
		return nil, fmt.Errorf("error updating value on server: %w", err)
	}
	return v.writeThrough(sess, func(c Cache) error {
		return c.Put(cache.Entry{ID: id, Version: version, Header: s.Header}, &body)
	}), nil
}

// Delete удаляет запись на сервере и в кэше. Ссылка разрешается по свежему кэшу; при недоступном сервере - ошибка.
func (v *Vault) Delete(ctx context.Context, ref string) (warnings []string, err error) {
	st, err := v.begin(ctx, ReadOptions{}, true)
	if err != nil {
		return nil, err
	}
	item, err := resolveIn(st.cache, ref)
	if err != nil {
		return nil, fmt.Errorf("error resolving record: %w", err)
	}

	err = v.srv.Delete(ctx, st.sess.Token, item.ID, item.Version)
	if err != nil {
		return nil, fmt.Errorf("error deleting record %s: %w", ref, err)
	}
	warnings = st.warnings
	if err := st.cache.Remove(item.ID); err != nil {
		warnings = append(warnings, cacheWriteWarning(err))
	}
	return warnings, nil
}

// writeThrough открывает кэш и применяет к нему запись после успешного вызова сервера.
// Сбой кэша не отменяет результат: он возвращается предупреждением, а следующий sync кэш починит.
func (v *Vault) writeThrough(sess session.Session, write func(Cache) error) []string {
	c, err := v.openCache(sess.ServerAddr, sess.UserID)
	var warnings []string
	if c == nil {
		return []string{cacheWriteWarning(err)}
	}
	if err := write(c); err != nil {
		warnings = append(warnings, cacheWriteWarning(err))
	}
	return warnings
}

func cacheWriteWarning(err error) string {
	return fmt.Sprintf("local cache was not updated, the next sync will repair it: %v", err)
}

// openSession загружает сессию. При checkExpiry=false срок токена не проверяется (режим offline).
func (v *Vault) openSession(checkExpiry bool) (session.Session, *crypto.Sealer, error) {
	sess, err := v.store.Load(v.serverAddr)
	if err != nil {
		return sess, nil, fmt.Errorf("error opening session: %w", err)
	}
	if checkExpiry && time.Now().After(sess.ExpiresAt) {
		return sess, nil, fmt.Errorf("token is expired, need to relogin: %w", domain.ErrSessionExpired)
	}

	sealer, err := crypto.NewSealer(sess.EncKey)
	if err != nil {
		return sess, nil, fmt.Errorf("error creating sealer: %w", err)
	}
	return sess, sealer, nil
}

func (v *Vault) seal(sl *crypto.Sealer, userID, id string, s domain.Secret) (body crypto.Sealed, err error) {
	bb, err := s.Marshal()
	if err != nil {
		return body, fmt.Errorf("error marshalling secret: %w", err)
	}
	if len(bb)+crypto.Overhead > v.bodySizeLimit {
		return body, fmt.Errorf("secret body is too big: %w", domain.ErrTooLarge)
	}
	if body, err = sl.Seal(userID, id, crypto.PartBody, bb); err != nil {
		return body, fmt.Errorf("error sealing body: %w", err)
	}
	return body, nil
}

func newID() string {
	return uuid.New().String()
}
