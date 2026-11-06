package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecret_Validate(t *testing.T) {
	tests := []struct {
		name    string
		secret  Secret
		wantErr bool
	}{
		{"ok", Secret{Header: Header{Type: TypeText, Name: "n"}, Content: Text("x")}, false},
		{"empty name", Secret{Header: Header{Type: TypeText}, Content: Text("x")}, true},
		{"nil content", Secret{Header: Header{Type: TypeText, Name: "n"}}, true},
		{"type mismatch", Secret{Header: Header{Type: TypeLogin, Name: "n"}, Content: Text("x")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.secret.Validate()
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidData)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSecret_MarshalRoundTrip(t *testing.T) {
	meta := []MetaItem{{"b", "2"}, {"a", "1"}, {"b", "3"}} // порядок и дубликаты ключей сохраняются
	tests := []struct {
		name string
		typ  RecType
		c    Content
	}{
		{"login", TypeLogin, Login{Username: "u", Password: "p"}},
		{"text", TypeText, Text("свободный текст")},
		{"binary", TypeBinary, Binary{Filename: "f.bin", Data: []byte{0, 1, 2, 0xff, 0}}},
		{"card", TypeCard, Card{Number: "4111", Holder: "H", Expiry: "01/30", CVV: "123"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := Secret{Header: Header{Type: tt.typ, Name: "name", Meta: meta}, Content: tt.c}

			hb, bb, err := want.Marshal()
			require.NoError(t, err)

			got, err := Unmarshal(hb, bb)
			require.NoError(t, err)
			assert.Equal(t, want, got)

			h, err := UnmarshalHeader(hb)
			require.NoError(t, err)
			assert.Equal(t, want.Header, h)
		})
	}
}

func TestSecret_Marshal_Invalid(t *testing.T) {
	_, _, err := Secret{Header: Header{Type: TypeText}, Content: Text("x")}.Marshal()
	assert.ErrorIs(t, err, ErrInvalidData)
}

func TestUnmarshal_Garbage(t *testing.T) {
	good, goodBody, err := Secret{
		Header:  Header{Type: TypeText, Name: "n"},
		Content: Text("x"),
	}.Marshal()
	require.NoError(t, err)
	garbage := []byte{0xff, 0xff, 0xff, 0xff}

	tests := []struct {
		name         string
		header, body []byte
	}{
		{"garbage header", garbage, goodBody},
		{"garbage body", good, garbage},
		{"empty body has no content", good, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal(tt.header, tt.body)
			assert.Error(t, err)
		})
	}

	_, err = UnmarshalHeader(garbage)
	assert.Error(t, err)
}
