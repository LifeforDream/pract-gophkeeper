package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadInputLine(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"lf", "abc\n", "abc", nil},
		{"crlf", "abc\r\n", "abc", nil},
		{"no newline", "abc", "abc", nil},
		{"empty line", "\n", "", nil},
		{"spaces kept", "  a b  \n", "  a b  ", nil},
		{"bom stripped", "\uFEFFabc\n", "abc", nil},
		{"cr in the middle kept", "a\rb\n", "a\rb", nil},
		{"eof only", "", "", io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readInputLine(bufio.NewReader(strings.NewReader(tt.in)))
			assert.Equal(t, tt.want, got)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestReadInputLine_ConsecutiveLines(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("one\r\ntwo"))

	first, err := readInputLine(r)
	require.NoError(t, err)
	second, err := readInputLine(r)
	require.NoError(t, err)
	_, err = readInputLine(r)

	assert.Equal(t, []string{"one", "two"}, []string{first, second})
	assert.ErrorIs(t, err, io.EOF)
}

// newPipeTerminal возвращает StdTerminal, читающий из канала (не из терминала), и буфер stderr.
func newPipeTerminal(t *testing.T, input string) (*StdTerminal, *bytes.Buffer) {
	t.Helper()
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = pr.Close() })
	_, err = pw.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, pw.Close())

	var stderr, stdout bytes.Buffer
	return &StdTerminal{in: pr, out: &stdout, err: &stderr, r: bufio.NewReader(pr)}, &stderr
}

func TestStdTerminal_NonInteractive(t *testing.T) {
	term, stderr := newPipeTerminal(t, "bob\npw\r\n")

	assert.False(t, term.Interactive())

	line, err := term.ReadLine(context.Background(), "Login: ")
	require.NoError(t, err)
	assert.Equal(t, "bob", line)

	secret, err := term.ReadSecret(context.Background(), "Password: ")
	require.NoError(t, err)
	assert.Equal(t, "pw", string(secret))

	assert.Equal(t, "Login: Password: ", stderr.String(), "приглашения идут в stderr")
}

func TestStdTerminal_EOF(t *testing.T) {
	term, _ := newPipeTerminal(t, "")

	_, err := term.ReadLine(context.Background(), "> ")
	assert.ErrorIs(t, err, io.EOF)
	_, err = term.ReadSecret(context.Background(), "> ")
	assert.ErrorIs(t, err, io.EOF)
}

func TestStdTerminal_CancelledIsSticky(t *testing.T) {
	term, stderr := newPipeTerminal(t, "bob\n")
	term.cancelled.Store(true)

	_, err := term.ReadLine(context.Background(), "Login: ")
	assert.ErrorIs(t, err, context.Canceled)
	_, err = term.ReadSecret(context.Background(), "Password: ")
	assert.ErrorIs(t, err, context.Canceled)

	assert.Empty(t, stderr.String(), "после отмены приглашения не печатаются")
}

func TestStdTerminal_Streams(t *testing.T) {
	term, _ := newPipeTerminal(t, "")

	assert.NotNil(t, term.Stdout())
	assert.NotNil(t, term.Stderr())
	assert.NotNil(t, term.Stdin())
	assert.NotNil(t, NewStdTerminal())
}
