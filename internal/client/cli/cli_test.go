package cli

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

const globalOptionsMarker = "GLOBAL-OPTIONS-MARKER"

// usageMarkers возвращает фрагменты, которые обязаны быть в общей справке.
func usageMarkers() []string {
	markers := []string{"Usage", globalOptionsMarker}
	for _, c := range commandsHelp() {
		markers = append(markers, c.name)
	}
	return markers
}

func TestRun_Dispatch(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout []string // пустой срез — stdout должен быть пуст
		stderr []string // пустой срез — stderr должен быть пуст
	}{
		{"no args", nil, 2, usageMarkers(), nil},
		{"help", []string{"help"}, 0, usageMarkers(), nil},
		{"--help", []string{"--help"}, 0, usageMarkers(), nil},
		{"unknown command", []string{"frobnicate"}, 2, nil, append(usageMarkers(), "unknown command: frobnicate\n")},
		{"version", []string{"version"}, 0, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.cli = New(h.auth, h.vault, h.term, WithGlobalOptionsHelp(func(w io.Writer) {
				fmt.Fprint(w, globalOptionsMarker)
			}))

			assert.Equal(t, tt.code, h.run(tt.args...))

			for stream, want := range map[string][]string{"stdout": tt.stdout, "stderr": tt.stderr} {
				got := h.term.out.String()
				if stream == "stderr" {
					got = h.term.errOut.String()
				}
				if len(want) == 0 {
					assert.Empty(t, got, stream)
				}
				for _, w := range want {
					assert.Contains(t, got, w, stream)
				}
			}
		})
	}
}

// TestRun_RendersCommandError проверяет связку: ошибка команды превращается в сообщение
// с переводом строки в stderr и код выхода. Сами соответствия описаны в TestRenderError.
func TestRun_RendersCommandError(t *testing.T) {
	h := newHarness(t)
	h.auth.err = domain.ErrNotFound

	assert.Equal(t, 1, h.run("logout"))
	assert.Equal(t, "record not found\n", h.term.errOut.String())
	assert.Empty(t, h.term.out.String())
}
