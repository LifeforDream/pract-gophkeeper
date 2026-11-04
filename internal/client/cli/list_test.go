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

func TestList(t *testing.T) {
	h := newHarness(t)
	h.vault.list = app.ListResult{Items: []app.Item{
		item("id-1", "mail", domain.TypeLogin, 3),
		item("id-2", "note", domain.TypeText, 1),
	}}

	assert.Equal(t, 0, h.run("list"))

	out := h.term.out.String()
	for _, want := range []string{"id-1", "mail", "login", "id-2", "note", "text"} {
		assert.Contains(t, out, want)
	}
	assert.Equal(t, 1, strings.Count(out, "Found Items"), "заголовок печатается один раз")
	assert.Empty(t, h.term.errOut.String())
}

func TestList_SkippedIsWarningNotFailure(t *testing.T) {
	tests := []struct {
		name  string
		items []app.Item
	}{
		{"with items", []app.Item{item("id-1", "mail", domain.TypeLogin, 1)}},
		{"without items", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.list = app.ListResult{Items: tt.items, Skipped: []string{"bad-1", "bad-2"}}

			assert.Equal(t, 0, h.run("list"))

			errOut := h.term.errOut.String()
			assert.Contains(t, errOut, "bad-1")
			assert.Contains(t, errOut, "bad-2")
			assert.Equal(t, 1, strings.Count(errOut, "Warning"), "предупреждение печатается один раз")
		})
	}
}

func TestList_Empty(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, 0, h.run("list"))
	assert.Empty(t, h.term.errOut.String())
}

func TestList_VaultError(t *testing.T) {
	h := newHarness(t)
	h.vault.listErr = domain.ErrSessionExpired

	assert.Equal(t, 1, h.run("list"))
	assert.Empty(t, h.term.out.String())
}
