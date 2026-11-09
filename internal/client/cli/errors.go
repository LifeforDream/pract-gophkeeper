package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func renderError(err error) (string, int) {
	var ambError *app.AmbiguousError
	var inpError userInputError
	switch {
	case errors.Is(err, domain.ErrSessionExpired):
		return "session expired, run `login`", 1
	case errors.Is(err, domain.ErrNoSession):
		return "unauthenticated, run `login`", 1
	case errors.Is(err, domain.ErrConflict):
		return "record version is too old, please refresh", 1
	case errors.Is(err, domain.ErrInvalidCredentials):
		return "login or password is incorrect, try again", 1
	case errors.Is(err, domain.ErrLoginTaken):
		return "login is taken by another user, please try something else", 1
	case errors.Is(err, domain.ErrNotFound):
		return "record not found", 1
	case errors.Is(err, domain.ErrTooLarge):
		return "record size is bigger than limits, try compressing or smaller body", 1
	case errors.Is(err, domain.ErrBodyNotCached):
		return "body is not cached, retry when the server is reachable", 1
	case errors.Is(err, domain.ErrUnavailable):
		return "server is unavailable", 1
	case errors.Is(err, domain.ErrServerMismatch):
		return "found credentials to another server, try login", 1
	case errors.As(err, &ambError):
		return fmt.Sprintf("id or name %s returned multiple values: %v", ambError.Name, ambError.IDs), 1
	case errors.As(err, &inpError):
		return inpError.message, 2
	case errors.Is(err, domain.ErrInvalidData):
		return "invalid data provided", 2
	case errors.Is(err, flag.ErrHelp):
		return "", 0
	case errors.Is(err, context.Canceled):
		return "canceled", 130
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "", 2
	default:
		return "internal error", 1
	}
}
