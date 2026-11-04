package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func TestRenderError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
		code     int
	}{
		{"session expired", domain.ErrSessionExpired, "login", 1},
		{"no session", domain.ErrNoSession, "login", 1},
		{"conflict", domain.ErrConflict, "version", 1},
		{"invalid credentials", domain.ErrInvalidCredentials, "incorrect", 1},
		{"login taken", domain.ErrLoginTaken, "taken", 1},
		{"not found", domain.ErrNotFound, "not found", 1},
		{"too large", domain.ErrTooLarge, "limit", 1},
		{"server mismatch", domain.ErrServerMismatch, "another server", 1},
		{"wrapped", fmt.Errorf("outer: %w", domain.ErrNotFound), "not found", 1},
		{"ambiguous", &app.AmbiguousError{Name: "mail", IDs: []string{"id1", "id2"}}, "id2", 1},
		{"wrapped user input", fmt.Errorf("outer: %w", userInputError{"name is empty"}), "name is empty", 2},
		{"invalid data", domain.ErrInvalidData, "invalid data", 2},
		{"help", flag.ErrHelp, "", 0},
		{"canceled", context.Canceled, "canceled", 130},
		{"eof", io.EOF, "", 2},
		{"unexpected eof", io.ErrUnexpectedEOF, "", 2},
		{"unknown", errBoom, "internal error", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, code := renderError(tt.err)
			assert.Contains(t, text, tt.contains)
			assert.Equal(t, tt.code, code)
		})
	}
}

func TestRenderError_UserInputShowsOnlyMessage(t *testing.T) {
	text, code := renderError(userInputError{"name is empty"})
	assert.Equal(t, "name is empty", text, "префикс из Error() не должен попадать в вывод")
	assert.Equal(t, 2, code)
}

func TestRenderError_DoesNotLeakDetails(t *testing.T) {
	text, _ := renderError(fmt.Errorf("db password=hunter2: %w", errBoom))
	assert.NotContains(t, text, "hunter2")
}
