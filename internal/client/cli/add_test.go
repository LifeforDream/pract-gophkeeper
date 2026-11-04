package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func TestAdd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "photo.bin")
	require.NoError(t, os.WriteFile(file, []byte{1, 2, 3}, 0o600))

	tests := []struct {
		name    string
		args    []string
		lines   []string
		secrets []string
		want    domain.Secret
	}{
		{
			name:    "login",
			args:    []string{"add", "login", "--name", "mail"},
			lines:   []string{"bob"},
			secrets: []string{"pw"},
			want: domain.Secret{
				Header:  domain.Header{Type: domain.TypeLogin, Name: "mail"},
				Content: domain.Login{Username: "bob", Password: "pw"},
			},
		},
		{
			name:  "text",
			args:  []string{"add", "text", "--name", "note"},
			lines: []string{"hello"},
			want: domain.Secret{
				Header:  domain.Header{Type: domain.TypeText, Name: "note"},
				Content: domain.Text("hello"),
			},
		},
		{
			name:    "card",
			args:    []string{"add", "card", "--name", "visa"},
			lines:   []string{"BOB", "12/30"},
			secrets: []string{"4111111111111111", "123"},
			want: domain.Secret{
				Header:  domain.Header{Type: domain.TypeCard, Name: "visa"},
				Content: domain.Card{Number: "4111111111111111", Holder: "BOB", Expiry: "12/30", CVV: "123"},
			},
		},
		{
			name: "binary",
			args: []string{"add", "binary", "--name", "pic", "--file", file},
			want: domain.Secret{
				Header:  domain.Header{Type: domain.TypeBinary, Name: "pic"},
				Content: domain.Binary{Filename: "photo.bin", Data: []byte{1, 2, 3}},
			},
		},
		{
			name:  "meta is repeatable",
			args:  []string{"add", "text", "--name", "note", "--meta", "a=1", "--meta", "b=2"},
			lines: []string{"hello"},
			want: domain.Secret{
				Header: domain.Header{
					Type: domain.TypeText, Name: "note",
					Meta: []domain.MetaItem{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}},
				},
				Content: domain.Text("hello"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.term.lines, h.term.secrets = tt.lines, tt.secrets

			require.Equal(t, 0, h.run(tt.args...), h.term.errOut.String())

			require.Len(t, h.vault.added, 1)
			got := h.vault.added[0]
			assert.Equal(t, tt.want.Content, got.Content)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.ElementsMatch(t, tt.want.Meta, got.Meta, "порядок меты не важен")
			assert.Contains(t, h.term.out.String(), "new-id", "id новой записи должен быть выведен")
		})
	}
}

func TestAdd_Errors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		lines   []string
		secrets []string
		vaulErr error
	}{
		{"no type", []string{"add"}, nil, nil, nil},
		{"unknown type", []string{"add", "pigeon", "--name", "x"}, nil, nil, nil},
		{"no name", []string{"add", "text"}, []string{"hello"}, nil, nil},
		{"bad meta", []string{"add", "text", "--name", "x", "--meta", "novalue"}, []string{"hello"}, nil, nil},
		{"binary without file", []string{"add", "binary", "--name", "x"}, nil, nil, nil},
		{"binary file missing", []string{"add", "binary", "--name", "x", "--file", "/no/such/file"}, nil, nil, nil},
		{"login input fails", []string{"add", "login", "--name", "x"}, nil, nil, nil},
		{"vault error", []string{"add", "text", "--name", "x"}, []string{"hello"}, nil, errBoom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.term.lines, h.term.secrets, h.vault.addErr = tt.lines, tt.secrets, tt.vaulErr

			assert.NotZero(t, h.run(tt.args...))
			if tt.vaulErr == nil {
				assert.Empty(t, h.vault.added, "в хранилище ничего не должно уйти")
			}
			assert.NotContains(t, h.term.out.String(), "added", "об успехе сообщать нельзя")
		})
	}
}

func TestSplitMeta(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []domain.MetaItem
		wantErr bool
	}{
		{"empty", nil, nil, false},
		{"pairs keep order", []string{"b=2", "a=1"}, []domain.MetaItem{{Key: "b", Value: "2"}, {Key: "a", Value: "1"}}, false},
		{"empty value", []string{"a="}, []domain.MetaItem{{Key: "a", Value: ""}}, false},
		{"value with equals", []string{"url=http://x?a=b"}, []domain.MetaItem{{Key: "url", Value: "http://x?a=b"}}, false},
		{"duplicate keys are kept", []string{"a=1", "a=2"}, []domain.MetaItem{{Key: "a", Value: "1"}, {Key: "a", Value: "2"}}, false},
		{"no equals", []string{"a"}, nil, true},
		{"empty key", []string{"=1"}, nil, true},
		{"error on any bad item", []string{"a=1", "oops"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitMeta(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if len(tt.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
