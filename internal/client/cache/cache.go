// Package cache хранит локальный кэш клиента: заголовки записей в открытом виде и зашифрованные тела.
//
// Кэш не содержит ничего, чего не было бы на сервере: расшифрованные тела, enc_key, токен и пароль сюда не попадают.
// Индекс лежит в cache.json, тела - по одному файлу в каталоге bodies.
// Тело записывается раньше индекса, который на него ссылается, а читатель доверяет телу только при совпадении версии.
package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

const (
	indexFile = "cache.json"
	bodiesDir = "bodies"
	tmpSuffix = ".tmp"
)

// ErrCorrupt означает, что индекс нечитаем. Open в этом случае возвращает рабочий пустой кэш вместе с этой ошибкой.
var ErrCorrupt = errors.New("cache index is corrupted")

// Entry - запись кэша: заголовок и версия, как их вернул сервер.
type Entry struct {
	ID       string
	Version  int64
	Revision int64 // 0 - ревизия неизвестна (запись сделана этим клиентом): такие записи идут в конце списка.
	Header   domain.Header
}

// indexRec - запись индекса на диске.
type indexRec struct {
	Entry
	BodyVersion int64 `json:"bodyVersion"` // версия закэшированного тела; имеет смысл только при HasBody.
	HasBody     bool  `json:"hasBody"`     // есть ли тело в кэше.
}

// indexDoc - содержимое cache.json.
type indexDoc struct {
	ServerAddr     string     `json:"serverAddr"`
	UserID         string     `json:"userID"`
	LatestRevision int64      `json:"latestRevision"`
	Records        []indexRec `json:"records"`
}

// bodyDoc - содержимое файла тела: запечатанное тело ровно в том виде, как его вернул сервер.
type bodyDoc struct {
	Version    int64  `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Store - кэш на диске. Не потокобезопасен: используется из одной горутины.
type Store struct {
	dir        string
	serverAddr string
	userID     string
	latest     int64
	recs       map[string]indexRec
}

// Open открывает кэш в dir, привязанный к серверу и пользователю. При несовпадении привязки кэш очищается.
// Нечитаемый индекс считается пустым кэшем: возвращается рабочий Store и ошибка, оборачивающая ErrCorrupt.
// Файлы тел, на которые не ссылается индекс, удаляются.
func Open(dir, serverAddr, userID string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, bodiesDir), 0o700); err != nil {
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}
	s := &Store{dir: dir, serverAddr: serverAddr, userID: userID, recs: map[string]indexRec{}}

	var openErr error
	data, err := os.ReadFile(filepath.Join(dir, indexFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("reading cache index: %w", err)
	default:
		var doc indexDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			openErr = fmt.Errorf("decoding %s: %w: %w", indexFile, ErrCorrupt, err)
		} else if doc.ServerAddr == serverAddr && doc.UserID == userID {
			s.latest = doc.LatestRevision
			for _, r := range doc.Records {
				if len(r.Header.Meta) == 0 {
					r.Header.Meta = nil
				}
				s.recs[r.ID] = r
			}
		}
	}

	if err := s.removeOrphans(); err != nil {
		return nil, err
	}
	return s, openErr
}

// LatestRevision возвращает ревизию, до которой кэш синхронизирован.
func (s *Store) LatestRevision() int64 { return s.latest }

// Entries возвращает живые записи в порядке ревизии; записи с неизвестной ревизией идут в конце.
func (s *Store) Entries() []Entry {
	out := make([]Entry, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, clone(r.Entry))
	}
	slices.SortFunc(out, func(a, b Entry) int {
		switch {
		case a.Revision == b.Revision:
			return strings.Compare(a.ID, b.ID)
		case a.Revision == 0:
			return 1
		case b.Revision == 0:
			return -1
		case a.Revision < b.Revision:
			return -1
		default:
			return 1
		}
	})
	return out
}

// Lookup возвращает запись по id.
func (s *Store) Lookup(id string) (Entry, bool) {
	r, ok := s.recs[id]
	if !ok {
		return Entry{}, false
	}
	return clone(r.Entry), true
}

// Body возвращает закэшированное тело, если его версия равна version. Отсутствующее, обрезанное или
// другой версии тело считается отсутствующим (ok=false), а не ошибкой.
func (s *Store) Body(id string, version int64) (body crypto.Sealed, ok bool, err error) {
	r, found := s.recs[id]
	if !found || !r.HasBody || r.BodyVersion != version {
		return crypto.Sealed{}, false, nil
	}
	data, err := os.ReadFile(s.bodyPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return crypto.Sealed{}, false, nil
		}
		return crypto.Sealed{}, false, fmt.Errorf("reading body file: %w", err)
	}
	var doc bodyDoc
	if err := json.Unmarshal(data, &doc); err != nil || doc.Version != version {
		return crypto.Sealed{}, false, nil
	}
	return crypto.Sealed{Nonce: doc.Nonce, Ciphertext: doc.Ciphertext}, true, nil
}

// Put сохраняет заголовок и версию записи. Если body не nil, он сохраняется как тело этой версии.
// Если body nil, прежнее тело остаётся только при совпадении его версии с e.Version, иначе сбрасывается.
// LatestRevision не меняется.
func (s *Store) Put(e Entry, body *crypto.Sealed) error {
	rec := indexRec{Entry: clone(e)}
	old, existed := s.recs[e.ID]
	switch {
	case body != nil:
		if err := s.writeBody(e.ID, e.Version, *body); err != nil {
			return err
		}
		rec.HasBody, rec.BodyVersion = true, e.Version
	case existed && old.HasBody && old.BodyVersion == e.Version:
		rec.HasBody, rec.BodyVersion = true, old.BodyVersion
	case existed && old.HasBody:
		if err := s.removeBody(e.ID); err != nil {
			return err
		}
	}
	s.recs[e.ID] = rec
	return s.save()
}

// PutBody сохраняет запечатанное тело записи вместе с его версией. Запись должна быть в кэше.
func (s *Store) PutBody(id string, version int64, body crypto.Sealed) error {
	r, ok := s.recs[id]
	if !ok {
		return fmt.Errorf("record %q is not in cache", id)
	}
	if err := s.writeBody(id, version, body); err != nil {
		return err
	}
	r.HasBody, r.BodyVersion = true, version
	s.recs[id] = r
	return s.save()
}

// Apply применяет ответ ListChanges: удаляет записи-надгробия вместе с телами, остальные сохраняет, сбрасывая тело,
// если его версия не совпала с новой.
// Если revision ниже закэшированной, кэш не меняется и возвращается ошибка, оборачивающая domain.ErrServerReset:
// вызывающий должен сделать Wipe и повторить запрос с нуля.
func (s *Store) Apply(revision int64, recs []domain.Record) error {
	if revision < s.latest {
		return fmt.Errorf("response revision %d, cached %d: %w", revision, s.latest, domain.ErrServerReset)
	}
	for _, r := range recs {
		if r.Deleted {
			if err := s.drop(r.ID); err != nil {
				return err
			}
			continue
		}
		next := indexRec{Entry: clone(Entry{ID: r.ID, Version: r.Version, Revision: r.Revision, Header: r.Header})}
		if old, ok := s.recs[r.ID]; ok && old.HasBody {
			if old.BodyVersion == r.Version {
				next.HasBody, next.BodyVersion = true, old.BodyVersion
			} else if err := s.removeBody(r.ID); err != nil {
				return err
			}
		}
		s.recs[r.ID] = next
	}
	s.latest = revision
	return s.save()
}

// Remove удаляет запись и её тело. Неизвестный id не ошибка.
func (s *Store) Remove(id string) error {
	if err := s.drop(id); err != nil {
		return err
	}
	return s.save()
}

// Wipe удаляет индекс и все тела. Сам каталог остаётся.
func (s *Store) Wipe() error {
	s.recs = map[string]indexRec{}
	s.latest = 0
	if err := os.Remove(filepath.Join(s.dir, indexFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cache index: %w", err)
	}
	return s.removeFilesIn(func(string) bool { return true })
}

// RemoveAll удаляет индекс и тела из dir, не трогая остальные файлы (в частности, сессию).
func RemoveAll(dir string) error {
	if err := os.Remove(filepath.Join(dir, indexFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cache index: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, bodiesDir)); err != nil {
		return fmt.Errorf("removing cache bodies: %w", err)
	}
	return nil
}

// drop убирает запись из памяти и удаляет файл её тела. Индекс не сохраняет.
func (s *Store) drop(id string) error {
	if err := s.removeBody(id); err != nil {
		return err
	}
	delete(s.recs, id)
	return nil
}

// save записывает индекс атомарно.
func (s *Store) save() error {
	doc := indexDoc{ServerAddr: s.serverAddr, UserID: s.userID, LatestRevision: s.latest, Records: make([]indexRec, 0, len(s.recs))}
	for _, r := range s.recs {
		doc.Records = append(doc.Records, r)
	}
	slices.SortFunc(doc.Records, func(a, b indexRec) int { return strings.Compare(a.ID, b.ID) })
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encoding cache index: %w", err)
	}
	return writeAtomic(filepath.Join(s.dir, indexFile), data)
}

func (s *Store) writeBody(id string, version int64, body crypto.Sealed) error {
	data, err := json.Marshal(bodyDoc{Version: version, Nonce: body.Nonce, Ciphertext: body.Ciphertext})
	if err != nil {
		return fmt.Errorf("encoding body: %w", err)
	}
	return writeAtomic(s.bodyPath(id), data)
}

func (s *Store) removeBody(id string) error {
	if err := os.Remove(s.bodyPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing body file: %w", err)
	}
	return nil
}

// bodyPath возвращает путь к файлу тела. Id приходит с сервера, поэтому в имени файла только хеш.
func (s *Store) bodyPath(id string) string {
	return filepath.Join(s.dir, bodiesDir, bodyName(id))
}

// bodyName - имя файла тела: hex от SHA-256 id записи.
func bodyName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// isBodyName сообщает, что имя выглядит как файл тела этого пакета.
func isBodyName(name string) bool {
	b, err := hex.DecodeString(name)
	return err == nil && len(b) == sha256.Size
}

// removeOrphans удаляет файлы тел, на которые не ссылается индекс, и остатки временных файлов.
// Чужие файлы в каталоге не трогаются.
func (s *Store) removeOrphans() error {
	referenced := make(map[string]struct{}, len(s.recs))
	for id := range s.recs {
		referenced[bodyName(id)] = struct{}{}
	}
	return s.removeFilesIn(func(name string) bool {
		if strings.HasSuffix(name, tmpSuffix) {
			return true
		}
		if !isBodyName(name) {
			return false
		}
		_, ok := referenced[name]
		return !ok
	})
}

// removeFilesIn удаляет в каталоге тел файлы, для которых del вернул true.
func (s *Store) removeFilesIn(del func(name string) bool) error {
	dir := filepath.Join(s.dir, bodiesDir)
	files, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.MkdirAll(dir, 0o700)
		}
		return fmt.Errorf("reading bodies dir: %w", err)
	}
	for _, f := range files {
		if f.IsDir() || !del(f.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, f.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", f.Name(), err)
		}
	}
	return nil
}

// writeAtomic пишет data во временный файл рядом с path и переименовывает его. При ошибке старый файл остаётся.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "*"+tmpSuffix)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := bytes.NewReader(data).WriteTo(tmp); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}
	ok = true
	return nil
}

// clone копирует запись, чтобы вызывающий не изменил срез меты внутри кэша.
func clone(e Entry) Entry {
	e.Header.Meta = slices.Clone(e.Header.Meta)
	return e
}
