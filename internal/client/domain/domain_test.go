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
		{"empty meta key", Secret{Header: Header{Type: TypeText, Name: "n", Meta: []MetaItem{{"", "v"}}}, Content: Text("x")}, true},
		{"duplicate meta key", Secret{Header: Header{Type: TypeText, Name: "n", Meta: []MetaItem{{"k", "1"}, {"k", "2"}}}, Content: Text("x")}, true},
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
	meta := []MetaItem{{"b", "2"}, {"a", "1"}}
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

			bb, err := want.Marshal()
			require.NoError(t, err)

			got, err := Unmarshal(want.Header, bb)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestSecret_Marshal_Invalid(t *testing.T) {
	_, err := Secret{Header: Header{Type: TypeText}, Content: Text("x")}.Marshal()
	assert.ErrorIs(t, err, ErrInvalidData)
}

func TestUnmarshal_Invalid(t *testing.T) {
	textHeader := Header{Type: TypeText, Name: "n"}
	goodBody, err := Secret{Header: textHeader, Content: Text("x")}.Marshal()
	require.NoError(t, err)

	tests := []struct {
		name   string
		header Header
		body   []byte
	}{
		{"garbage body", textHeader, []byte{0xff, 0xff, 0xff, 0xff}},
		{"empty body has no content", textHeader, nil},
		{"header type from server mismatches body", Header{Type: TypeLogin, Name: "n"}, goodBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal(tt.header, tt.body)
			assert.Error(t, err)
		})
	}
}
