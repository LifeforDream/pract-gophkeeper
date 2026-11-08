package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func item(id, name string, t domain.RecType, v int64) app.Item {
	return app.Item{ID: id, Header: domain.Header{Name: name, Type: t}, Version: v}
}

func TestSync(t *testing.T) {
	h := newHarness(t)
	h.vault.list = app.ListResult{Items: []app.Item{
		item("id-1", "mail", domain.TypeLogin, 3),
		item("id-2", "note", domain.TypeText, 1),
	}}

	assert.Equal(t, 0, h.run("sync"))

	out := h.term.out.String()
	for _, want := range []string{"id-1", "mail", "login", "id-2", "note", "text"} {
		assert.Contains(t, out, want)
	}
	assert.Equal(t, 1, strings.Count(out, "Found Items"), "заголовок печатается один раз")
	assert.Empty(t, h.term.errOut.String())
}

func TestSync_Empty(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, 0, h.run("sync"))
	assert.Empty(t, h.term.errOut.String())
}

func TestSync_VaultError(t *testing.T) {
	h := newHarness(t)
	h.vault.listErr = domain.ErrSessionExpired

	assert.Equal(t, 1, h.run("sync"))
	assert.Empty(t, h.term.out.String())
}

func TestList(t *testing.T) {
	h := newHarness(t)
	h.vault.found = app.ListResult{Items: []app.Item{item("id-2", "note", domain.TypeText, 1)}}

	assert.Equal(t, 0, h.run("list", "--type", "text", "--meta-key", "env", "--name", "no"))

	assert.Equal(t, domain.Filter{Type: domain.TypeText, MetaKey: "env", NameFragment: "no"}, h.vault.listFilter)
	out := h.term.out.String()
	assert.Contains(t, out, "id-2")
	assert.Equal(t, 1, strings.Count(out, "Found Items"), "вывод общий с sync")
	assert.Empty(t, h.term.errOut.String())
}

func TestList_NoFlags(t *testing.T) {
	h := newHarness(t)

	assert.Equal(t, 0, h.run("list"))
	assert.Equal(t, domain.Filter{}, h.vault.listFilter)
}

func TestList_Errors(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		vaultErr error
		wantCode int
	}{
		{"unknown type", []string{"list", "--type", "pigeon"}, nil, 2},
		{"unknown flag", []string{"list", "--bogus"}, nil, 2},
		{"positional argument", []string{"list", "mail"}, nil, 2},
		{"vault error", []string{"list"}, domain.ErrSessionExpired, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.findErr = tt.vaultErr

			assert.Equal(t, tt.wantCode, h.run(tt.args...))
			assert.Empty(t, h.term.out.String())
			if tt.vaultErr == nil {
				assert.False(t, h.vault.listCalled, "с неверным вводом сервер не вызывается")
			}
		})
	}
}
