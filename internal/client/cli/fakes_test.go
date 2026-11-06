package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

// fakeTerm — Terminal со скриптованными ответами. Когда ответы кончились, возвращает io.EOF.
type fakeTerm struct {
	out, errOut bytes.Buffer
	interactive bool
	lines       []string
	secrets     []string
	prompts     []string
}

func (f *fakeTerm) Stdout() io.Writer { return &f.out }
func (f *fakeTerm) Stderr() io.Writer { return &f.errOut }
func (f *fakeTerm) Stdin() io.Reader  { return strings.NewReader("") }
func (f *fakeTerm) Interactive() bool { return f.interactive }

func (f *fakeTerm) ReadLine(_ context.Context, prompt string) (string, error) {
	f.prompts = append(f.prompts, prompt)
	if len(f.lines) == 0 {
		return "", io.EOF
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l, nil
}

func (f *fakeTerm) ReadSecret(_ context.Context, prompt string) ([]byte, error) {
	f.prompts = append(f.prompts, prompt)
	if len(f.secrets) == 0 {
		return nil, io.EOF
	}
	s := f.secrets[0]
	f.secrets = f.secrets[1:]
	return []byte(s), nil
}

// fakeAuth запоминает аргументы вызовов. Пароль копируется, т.к. CLI зануляет слайс после вызова.
type fakeAuth struct {
	err error

	registerCalls, loginCalls, logoutCalls int
	login, password                        string
}

func (f *fakeAuth) Register(_ context.Context, login string, pw []byte) error {
	f.registerCalls++
	f.login, f.password = login, string(pw)
	return f.err
}

func (f *fakeAuth) Login(_ context.Context, login string, pw []byte) error {
	f.loginCalls++
	f.login, f.password = login, string(pw)
	return f.err
}

func (f *fakeAuth) Logout() error {
	f.logoutCalls++
	return f.err
}

// fakeVault запоминает аргументы вызовов и отдаёт заранее заданные ответы.
type fakeVault struct {
	addID  string
	addErr error
	added  []domain.Secret

	list    app.ListResult
	listErr error

	entry  app.Entry
	getErr error
	getRef string

	updateErr     error
	updateCalls   int
	updateID      string
	updateVersion int64
	updated       domain.Secret

	deleteErr   error
	deleteCalls int
	deleteRef   string
}

func (f *fakeVault) Add(_ context.Context, s domain.Secret) (string, error) {
	f.added = append(f.added, s)
	return f.addID, f.addErr
}

func (f *fakeVault) List(context.Context) (app.ListResult, error) { return f.list, f.listErr }

func (f *fakeVault) Get(_ context.Context, ref string) (app.Entry, error) {
	f.getRef = ref
	return f.entry, f.getErr
}

func (f *fakeVault) Update(_ context.Context, id string, v int64, s domain.Secret) error {
	f.updateCalls++
	f.updateID, f.updateVersion, f.updated = id, v, s
	return f.updateErr
}

func (f *fakeVault) Delete(_ context.Context, ref string) error {
	f.deleteCalls++
	f.deleteRef = ref
	return f.deleteErr
}

// newEntry собирает app.Entry из секрета.
func newEntry(id string, version int64, s domain.Secret) app.Entry {
	s.Header.Type = typeOf(s.Content)
	return app.Entry{ID: id, Header: s.Header, Version: version, Secret: s}
}

func typeOf(c domain.Content) domain.RecType {
	switch c.(type) {
	case domain.Login:
		return domain.TypeLogin
	case domain.Text:
		return domain.TypeText
	case domain.Binary:
		return domain.TypeBinary
	default:
		return domain.TypeCard
	}
}

// harness — CLI вместе со всеми фейками. Переменная окружения с паролем сброшена.
type harness struct {
	cli   *CLI
	term  *fakeTerm
	auth  *fakeAuth
	vault *fakeVault
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("GOPHKEEPER_PASSWORD", "")
	h := &harness{term: &fakeTerm{interactive: true}, auth: &fakeAuth{}, vault: &fakeVault{addID: "new-id"}}
	h.cli = New(h.auth, h.vault, h.term)
	return h
}

// run выполняет команду и возвращает код выхода.
func (h *harness) run(args ...string) int {
	return h.cli.Run(context.Background(), args)
}

var errBoom = errors.New("boom")
