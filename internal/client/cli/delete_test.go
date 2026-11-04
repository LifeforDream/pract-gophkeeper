package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func TestDelete_Confirmation(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		answer     []string
		wantPrompt bool
		wantDelete bool
	}{
		{"yes", []string{"delete", "mail"}, []string{"y"}, true, true},
		{"YES", []string{"delete", "mail"}, []string{"YES"}, true, true},
		{"no", []string{"delete", "mail"}, []string{"n"}, true, false},
		{"empty answer is no", []string{"delete", "mail"}, []string{""}, true, false},
		{"garbage is no", []string{"delete", "mail"}, []string{"maybe"}, true, false},
		{"--yes skips prompt", []string{"delete", "--yes", "mail"}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("x")))
			h.term.lines = tt.answer

			assert.Equal(t, 0, h.run(tt.args...), h.term.errOut.String())

			assert.Equal(t, tt.wantPrompt, len(h.term.prompts) > 0)
			if tt.wantDelete {
				assert.Equal(t, 1, h.vault.deleteCalls)
				assert.Equal(t, "id-1", h.vault.deleteRef, "удаление идёт по id, а не по имени")
				assert.Contains(t, h.term.out.String(), "deleted")
			} else {
				assert.Zero(t, h.vault.deleteCalls)
				assert.Contains(t, h.term.out.String(), "Cancelling")
				assert.NotContains(t, h.term.out.String(), "deleted")
			}
		})
	}
}

func TestDelete_Errors(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		getErr    error
		deleteErr error
		lines     []string
		exit      int
	}{
		{"no ref", []string{"delete"}, nil, nil, nil, 2},
		{"get fails", []string{"delete", "x"}, domain.ErrNotFound, nil, nil, 1},
		{"prompt fails", []string{"delete", "x"}, nil, nil, nil, 2},
		{"delete fails", []string{"delete", "x"}, nil, domain.ErrConflict, []string{"y"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.vault.entry = newEntry("id-1", 1, secretOf("mail", domain.Text("x")))
			h.vault.getErr, h.vault.deleteErr = tt.getErr, tt.deleteErr
			h.term.lines = tt.lines

			assert.Equal(t, tt.exit, h.run(tt.args...))
			assert.NotContains(t, h.term.out.String(), "deleted")
		})
	}
}
