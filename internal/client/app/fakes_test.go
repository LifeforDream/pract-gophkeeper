package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/session"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testAddr   = "srv:1"
	testUserID = "user-1"
	testToken  = "valid-token"
)

// testKDF — дешёвые параметры Argon2id.
var testKDF = kdfparams.Params{MemoryKiB: kdfparams.MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}

// memStore — fake session.Store в памяти.
type memStore struct {
	mu       sync.Mutex
	sess     *session.Session
	saves    int
	saveErr  error
	clearErr error
}

func (m *memStore) Load(addr string) (session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess == nil {
		return session.Session{}, domain.ErrNoSession
	}
	if m.sess.ServerAddr != addr {
		return session.Session{}, domain.ErrServerMismatch
	}
	return *m.sess, nil
}

func (m *memStore) Save(s session.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.sess = &s
	m.saves++
	return nil
}

func (m *memStore) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clearErr != nil {
		return m.clearErr
	}
	m.sess = nil
	return nil
}

// fakeVault — fake VaultServer поверх map. Ведёт себя как настоящий сервер:
// проверяет токен, версии и скрывает tombstone'ы в ListChanges(0).
type fakeVault struct {
	mu       sync.Mutex
	token    string // ожидаемый токен
	recs     map[string]domain.Record
	revision int64
	putCalls int

	listFilter domain.Filter // фильтр последнего вызова List
}

func newFakeVault() *fakeVault {
	return &fakeVault{token: testToken, recs: map[string]domain.Record{}}
}

func (f *fakeVault) auth(token string) error {
	if token != f.token {
		return domain.ErrSessionExpired
	}
	return nil
}

func (f *fakeVault) Put(_ context.Context, token, id string, expected int64, h domain.Header, b crypto.Sealed) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.auth(token); err != nil {
		return 0, err
	}
	f.putCalls++
	cur, exists := f.recs[id]
	switch {
	case expected == 0 && exists && !cur.Deleted:
		return 0, domain.ErrConflict
	case expected != 0 && (!exists || cur.Deleted):
		return 0, domain.ErrNotFound
	case expected != 0 && cur.Version != expected:
		return 0, domain.ErrConflict
	}
	f.revision++
	f.recs[id] = domain.Record{ID: id, Header: h, Body: b, Version: cur.Version + 1, Revision: f.revision}
	return cur.Version + 1, nil
}

func (f *fakeVault) Delete(_ context.Context, token, id string, expected int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.auth(token); err != nil {
		return err
	}
	cur, ok := f.recs[id]
	if !ok || cur.Deleted {
		return domain.ErrNotFound
	}
	if cur.Version != expected {
		return domain.ErrConflict
	}
	f.revision++
	cur.Deleted, cur.Version, cur.Revision = true, cur.Version+1, f.revision
	f.recs[id] = cur
	return nil
}

func (f *fakeVault) Get(_ context.Context, token, id string) (domain.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.auth(token); err != nil {
		return domain.Record{}, err
	}
	cur, ok := f.recs[id]
	if !ok || cur.Deleted {
		return domain.Record{}, domain.ErrNotFound
	}
	return cur, nil
}

func (f *fakeVault) ListChanges(_ context.Context, token string, since int64) (int64, []domain.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.auth(token); err != nil {
		return 0, nil, err
	}
	var out []domain.Record
	for _, r := range f.recs {
		if r.Revision <= since || (since == 0 && r.Deleted) {
			continue
		}
		r.Body = crypto.Sealed{} // как настоящий сервер: тела в списке нет
		out = append(out, r)
	}
	return f.revision, out, nil
}

// List запоминает фильтр и отдаёт живые записи с именем, содержащим NameFragment.
// Остальную семантику фильтра проверяют нижние слои, здесь важно только, что фильтр дошёл до транспорта.
func (f *fakeVault) List(_ context.Context, token string, filter domain.Filter) ([]domain.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listFilter = filter
	if err := f.auth(token); err != nil {
		return nil, err
	}
	var out []domain.Record
	for _, r := range f.recs {
		if r.Deleted || !strings.Contains(r.Name, filter.NameFragment) {
			continue
		}
		r.Body = crypto.Sealed{}
		out = append(out, r)
	}
	return out, nil
}

// fakeAuth — fake AuthServer, запоминает аргументы вызовов.
type fakeAuth struct {
	salt   []byte
	params kdfparams.Params
	token  string

	getErr, regErr, loginErr error

	regLogin    string
	regAuthKey  []byte
	regSalt     []byte
	regParams   kdfparams.Params
	loginKey    []byte
	loginCalled bool
}

func (f *fakeAuth) GetKDFParams(context.Context, string) ([]byte, kdfparams.Params, error) {
	return f.salt, f.params, f.getErr
}

func (f *fakeAuth) Register(_ context.Context, login string, authKey, salt []byte, p kdfparams.Params) (string, error) {
	f.regLogin, f.regAuthKey, f.regSalt, f.regParams = login, authKey, salt, p
	return f.token, f.regErr
}

func (f *fakeAuth) Login(_ context.Context, _ string, authKey []byte) (string, error) {
	f.loginCalled = true
	f.loginKey = authKey
	return f.token, f.loginErr
}

// makeJWT выпускает неподписанный по-настоящему токен: клиент всё равно не проверяет подпись.
func makeJWT(claims jwt.MapClaims) string {
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("k"))
	if err != nil {
		panic(fmt.Sprintf("sign jwt: %v", err))
	}
	return s
}

func validJWT(userID string, exp time.Time) string {
	return makeJWT(jwt.MapClaims{"sub": userID, "exp": exp.Unix()})
}
