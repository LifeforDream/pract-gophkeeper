// Package userid хранит методы для работы с userid в контексте.
package userid

import "context"

type userKey struct{}

// NewContext создаёт новый контекст со значением userID.
func NewContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userKey{}, userID)
}

// FromContext достаёт из контекста userID вместе с "ok", позволяющим проверить наличие.
func FromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userKey{}).(string)
	return userID, ok
}
