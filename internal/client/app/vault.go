package app

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

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
}

// ListResult представляет из себя список записей без Body.
type ListResult struct {
	Items []Item // список секретов с заголовками.
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
	serverAddr    string
	bodySizeLimit int
}

// NewVault собирает и возвращает рабочий экземпляр Vault.
func NewVault(srv VaultServer, store session.Store, serverAddr string, bodySizeLimit int) (*Vault, error) {
	if bodySizeLimit <= 0 {
		return nil, errors.New("size limits should be positive")
	}
	return &Vault{
		srv:           srv,
		store:         store,
		serverAddr:    serverAddr,
		bodySizeLimit: bodySizeLimit,
	}, nil
}

// DefaultBodySizeLimit предлагает значение "по умолчанию" предела размера тела.
func DefaultBodySizeLimit() int {
	return 1024 * 1024 // 1 MiB
}

// Add добавляет запись на сервер.
func (v *Vault) Add(ctx context.Context, s domain.Secret) (id string, err error) {
	sess, sealer, err := v.open()
	if err != nil {
		return "", fmt.Errorf("error opening session: %w", err)
	}
	id = newID()

	body, err := v.seal(sealer, sess.UserID, id, s)
	if err != nil {
		return "", fmt.Errorf("error sealing secret in add: %w", err)
	}

	_, err = v.srv.Put(ctx, sess.Token, id, 0, s.Header, body)
	if err != nil {
		return "", fmt.Errorf("error putting new record on server: %w", err)
	}
	return id, nil
}

// List получает список записей с сервера без Body.
func (v *Vault) List(ctx context.Context) (ListResult, error) {
	sess, _, err := v.open()
	if err != nil {
		return ListResult{}, fmt.Errorf("error opening session: %w", err)
	}
	_, recs, err := v.srv.ListChanges(ctx, sess.Token, 0)
	if err != nil {
		return ListResult{}, fmt.Errorf("error retrieving records from server: %w", err)
	}
	result := ListResult{Items: make([]Item, 0, len(recs))}
	for _, record := range recs {
		result.Items = append(result.Items, Item{ID: record.ID, Header: record.Header, Version: record.Version})
	}
	return result, nil
}

// Resolve нужен для определения, чем является ref: ID или именем записи.
// Для этого он запрашивает список всех записей пользователя и находит соответствие.
func (v *Vault) Resolve(ctx context.Context, ref string) (Item, error) {
	records, err := v.List(ctx)
	if err != nil {
		return Item{}, fmt.Errorf("error listing for resolve: %w", err)
	}
	var candidates []Item
	for _, record := range records.Items {
		if record.ID == ref {
			// ID точно побеждает
			return record, nil
		}
		if record.Header.Name == ref {
			candidates = append(candidates, record)
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

// Get получает и расшифровывает запись целиком.
func (v *Vault) Get(ctx context.Context, ref string) (Entry, error) {
	sess, sealer, err := v.open()
	if err != nil {
		return Entry{}, fmt.Errorf("error opening session: %w", err)
	}
	item, err := v.Resolve(ctx, ref)
	if err != nil {
		return Entry{}, fmt.Errorf("error resolving record: %w", err)
	}

	record, err := v.srv.Get(ctx, sess.Token, item.ID)
	if err != nil {
		return Entry{}, fmt.Errorf("error getting record body: %w", err)
	}

	bb, err := sealer.Open(sess.UserID, record.ID, crypto.PartBody, record.Body)
	if err != nil {
		return Entry{}, fmt.Errorf("error opening record body: %w", err)
	}
	sec, err := domain.Unmarshal(record.Header, bb)
	if err != nil {
		return Entry{}, fmt.Errorf("error unmarshalling secret: %w", err)
	}
	return Entry{
		ID:      record.ID,
		Header:  sec.Header,
		Version: record.Version,
		Secret:  sec,
	}, nil
}

// Update загружает новую версию записи на сервере.
func (v *Vault) Update(ctx context.Context, id string, expectedVersion int64, s domain.Secret) error {
	sess, sealer, err := v.open()
	if err != nil {
		return fmt.Errorf("error opening session: %w", err)
	}

	body, err := v.seal(sealer, sess.UserID, id, s)
	if err != nil {
		return fmt.Errorf("error sealing secret in update: %w", err)
	}

	_, err = v.srv.Put(ctx, sess.Token, id, expectedVersion, s.Header, body)

	if err != nil {
		return fmt.Errorf("error updating value on server: %w", err)
	}
	return nil
}

// Delete удаляет запись с сервера.
func (v *Vault) Delete(ctx context.Context, ref string) error {
	sess, _, err := v.open()
	if err != nil {
		return fmt.Errorf("error opening session: %w", err)
	}
	item, err := v.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("error resolving record: %w", err)
	}

	err = v.srv.Delete(ctx, sess.Token, item.ID, item.Version)
	if err != nil {
		return fmt.Errorf("error deleting record %s: %w", ref, err)
	}
	return nil
}

func (v *Vault) open() (session.Session, *crypto.Sealer, error) {
	sess, err := v.store.Load(v.serverAddr)
	if err != nil {
		return sess, nil, fmt.Errorf("error opening session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
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
