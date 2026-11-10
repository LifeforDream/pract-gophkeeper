package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func TestUpdate(t *testing.T) {
	oldMeta := domain.MetaItem{Key: "site", Value: "example.com"}
	tests := []struct {
		name    string
		old     domain.Content
		lines   []string // имя, мета, затем поля по типу
		secrets []string
		want    domain.Secret
	}{
		{
			name:    "login: empty answers keep everything",
			old:     domain.Login{Username: "bob", Password: "old"},
			lines:   []string{"", "", ""},
			secrets: []string{""},
			want:    secretOf("mail", domain.Login{Username: "bob", Password: "old"}, oldMeta),
		},
		{
			name:    "login: all fields changed",
			old:     domain.Login{Username: "bob", Password: "old"},
			lines:   []string{"work", "a=1", "alice"},
			secrets: []string{"new"},
			want:    secretOf("work", domain.Login{Username: "alice", Password: "new"}, domain.MetaItem{Key: "a", Value: "1"}),
		},
		{
			name:  "text: changed",
			old:   domain.Text("old"),
			lines: []string{"", "", "new"},
			want:  secretOf("mail", domain.Text("new"), oldMeta),
		},
		{
			name:  "text: empty keeps",
			old:   domain.Text("old"),
			lines: []string{"", "", ""},
			want:  secretOf("mail", domain.Text("old"), oldMeta),
		},
		{
			name:    "card: only holder changed",
			old:     domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "123"},
			lines:   []string{"", "", "ALICE", ""},
			secrets: []string{"", ""},
			want:    secretOf("mail", domain.Card{Number: "4111111111111111", Holder: "ALICE", Expiry: "12/30", CVV: "123"}, oldMeta),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 7, secretOf("mail", tt.old, oldMeta))
			h.term.lines, h.term.secrets = tt.lines, tt.secrets

			require.Equal(t, 0, h.run("update", "mail"), h.term.errOut.String())

			assert.Equal(t, 1, h.vault.updateCalls)
			assert.Equal(t, "id-1", h.vault.updateID)
			assert.Equal(t, int64(7), h.vault.updateVersion, "должна уходить версия, прочитанная в Get")
			assert.Equal(t, tt.want.Name, h.vault.updated.Name)
			assert.Equal(t, tt.want.Content, h.vault.updated.Content)
			assert.ElementsMatch(t, tt.want.Meta, h.vault.updated.Meta)
		})
	}
}

func TestUpdate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		getErr    error
		updateErr error
		lines     []string
		exit      int
	}{
		{"no ref", []string{"update"}, nil, nil, nil, 2},
		{"get fails", []string{"update", "x"}, domain.ErrNotFound, nil, nil, 1},
		{"name prompt fails", []string{"update", "x"}, nil, nil, nil, 2},
		{"bad meta", []string{"update", "x"}, nil, nil, []string{"", "novalue"}, 2},
		{"update fails", []string{"update", "x"}, nil, domain.ErrConflict, []string{"", "", "new"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("old")))
			h.vault.getErr, h.vault.updateErr = tt.getErr, tt.updateErr
			h.term.lines = tt.lines

			assert.Equal(t, tt.exit, h.run(tt.args...))
		})
	}
}

func TestUpdate_BinaryFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "new.bin")
	require.NoError(t, os.WriteFile(file, []byte{4, 5}, 0o600))
	old := domain.Binary{Filename: "a", Data: []byte{1}}

	tests := []struct {
		name string
		path string
		code int
		want domain.Content // nil — обновление не должно уйти в хранилище
	}{
		{"empty path keeps previous", "", 0, old},
		{"new file replaces content", file, 0, domain.Binary{Filename: "new.bin", Data: []byte{4, 5}}},
		{"unreadable file", "/no/such/file", 1, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("pic", old))
			h.term.lines = []string{"", "", tt.path}

			require.Equal(t, tt.code, h.run("update", "pic"), h.term.errOut.String())

			if tt.want == nil {
				assert.Zero(t, h.vault.updateCalls)
				return
			}
			assert.Equal(t, tt.want, h.vault.updated.Content)
		})
	}
}

func TestUpdate_CardPromptsFail(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		secrets []string
	}{
		{"number", []string{"", ""}, nil},
		{"holder", []string{"", ""}, []string{""}},
		{"expiry", []string{"", "", ""}, []string{""}},
		{"cvv", []string{"", "", "", ""}, []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("visa", domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "987"}))
			h.term.lines, h.term.secrets = tt.lines, tt.secrets

			assert.Equal(t, 2, h.run("update", "visa"), "EOF на приглашении — ошибка ввода")
			assert.Zero(t, h.vault.updateCalls)
		})
	}
}

func TestUpdate_CardKeepsPreviousValues(t *testing.T) {
	h := newHarness(t)
	old := domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "987"}
	h.vault.entry = newEntry("id-1", 1, secretOf("visa", old))
	h.term.lines, h.term.secrets = []string{"", "", "", ""}, []string{"", ""}

	require.Equal(t, 0, h.run("update", "visa"), h.term.errOut.String())

	assert.Equal(t, old, h.vault.updated.Content)
	for _, p := range h.term.prompts {
		assert.NotContains(t, p, old.Number, "номер в приглашении должен быть замаскирован")
	}
}
