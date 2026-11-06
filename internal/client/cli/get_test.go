package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func secretOf(name string, c domain.Content, meta ...domain.MetaItem) domain.Secret {
	return domain.Secret{Header: domain.Header{Name: name, Meta: meta}, Content: c}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		content domain.Content
		want    []string
		hidden  []string
	}{
		{
			name:    "login masked",
			args:    []string{"get", "mail"},
			content: domain.Login{Username: "bob", Password: "hunter2"},
			want:    []string{"bob"},
			hidden:  []string{"hunter2"},
		},
		{
			name:    "login shown",
			args:    []string{"get", "--show", "mail"},
			content: domain.Login{Username: "bob", Password: "hunter2"},
			want:    []string{"bob", "hunter2"},
		},
		{
			name:    "card masked",
			args:    []string{"get", "mail"},
			content: domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "987"},
			want:    []string{"BOB", "12/30"},
			hidden:  []string{"4111111111111111", "987"},
		},
		{
			name:    "card shown",
			args:    []string{"get", "--show", "mail"},
			content: domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "987"},
			want:    []string{"4111111111111111", "987"},
		},
		{
			name:    "text",
			args:    []string{"get", "mail"},
			content: domain.Text("my note"),
			want:    []string{"my note"},
		},
		{
			name:    "binary summary without out",
			args:    []string{"get", "mail"},
			content: domain.Binary{Filename: "a.bin", Data: []byte{1, 2, 3, 4, 5}},
			want:    []string{"a.bin", "5"},
			hidden:  []string{"Wrote"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 2, secretOf("mail", tt.content, domain.MetaItem{Key: "site", Value: "example.com"}))

			require.Equal(t, 0, h.run(tt.args...), h.term.errOut.String())

			out := h.term.out.String()
			assert.Equal(t, "mail", h.vault.getRef)
			for _, w := range append(tt.want, "id-1", "site", "example.com") {
				assert.Contains(t, out, w)
			}
			for _, w := range tt.hidden {
				assert.NotContains(t, out, w)
			}
		})
	}
}

func TestGet_BinaryOut(t *testing.T) {
	const old = "old content, longer"
	tests := []struct {
		name     string
		existing bool
		force    bool
		wantCode int
		want     []byte
	}{
		{"new file", false, false, 0, []byte{9, 8, 7}},
		{"existing file is refused without force", true, false, 2, []byte(old)},
		{"force truncates longer existing file", true, true, 0, []byte{9, 8, 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("pic", domain.Binary{Filename: "a.bin", Data: []byte{9, 8, 7}}))
			out := filepath.Join(t.TempDir(), "saved.bin")
			if tt.existing {
				require.NoError(t, os.WriteFile(out, []byte(old), 0o600))
			}
			args := []string{"get", "--out", out, "pic"}
			if tt.force {
				args = []string{"get", "--force", "--out", out, "pic"}
			}

			require.Equal(t, tt.wantCode, h.run(args...), h.term.errOut.String())

			data, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, tt.want, data)
			info, err := os.Stat(out)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			assert.NotContains(t, h.term.out.String(), "\x09\x08\x07", "содержимое файла в stdout не выводится")
			assert.Equal(t, tt.wantCode == 0, strings.Contains(h.term.out.String(), "Wrote"))
		})
	}
}

func TestGet_BinaryOutOpenError(t *testing.T) {
	h := newHarness(t)
	h.vault.entry = newEntry("id-1", 1, secretOf("pic", domain.Binary{Filename: "a.bin", Data: []byte{1}}))
	out := filepath.Join(t.TempDir(), "no-such-dir", "saved.bin")

	assert.Equal(t, 1, h.run("get", "--out", out, "pic"))
	assert.NotContains(t, h.term.out.String(), "Wrote", "об успехе сообщать нельзя")
}

func TestGet_Errors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		getErr error
		exit   int
	}{
		{"no ref", []string{"get"}, nil, 2},
		{"extra args", []string{"get", "x", "--show"}, nil, 2},
		{"vault fails", []string{"get", "x"}, domain.ErrNotFound, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.getErr = tt.getErr

			assert.Equal(t, tt.exit, h.run(tt.args...))
			assert.Empty(t, h.term.out.String())
		})
	}
}
