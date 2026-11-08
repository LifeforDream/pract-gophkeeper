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
