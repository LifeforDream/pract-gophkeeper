// Package userid хранит методы для работы с userid в контексте.
package userid

import (
	"context"
	"errors"
)

type userKey struct{}

// NewContext создаёт новый контекст со значением userID.
func NewContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userKey{}, userID)
}

// FromContext достаёт из контекста userID. В случае отсутствия значения или некорректного типа будет ошибка.
func FromContext(ctx context.Context) (string, error) {
	userID := ctx.Value(userKey{})
	if userID == nil {
		return "", errors.New("empty userKey in context")
	}
	userIDstr, ok := userID.(string)
	if !ok {
		return "", errors.New("invalid userKey type in context")
	}
	return userIDstr, nil
}
