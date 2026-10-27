package userid

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewContextFromContext(t *testing.T) {
	ctx := NewContext(context.Background(), "user-1")
	id, ok := FromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "user-1", id)
}

func TestFromContext_Missing(t *testing.T) {
	id, ok := FromContext(context.Background())
	assert.False(t, ok)
	assert.Empty(t, id)
}

type otherKey struct{}

func TestFromContext_ForeignValueIgnored(t *testing.T) {
	// Значение с ключом другого типа не должно читаться как userID.
	ctx := context.WithValue(context.Background(), otherKey{}, "intruder")
	_, ok := FromContext(ctx)
	assert.False(t, ok)
}

func TestNewContext_Overrides(t *testing.T) {
	ctx := NewContext(NewContext(context.Background(), "a"), "b")
	id, ok := FromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "b", id)
}
