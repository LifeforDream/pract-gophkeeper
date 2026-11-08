package userid

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewContextFromContext(t *testing.T) {
	ctx := NewContext(context.Background(), "user-1")
	id, err := FromContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "user-1", id)
}

func TestFromContext_Missing(t *testing.T) {
	id, err := FromContext(context.Background())
	assert.Error(t, err)
	assert.Empty(t, id)
}

type otherKey struct{}

func TestFromContext_ForeignValueIgnored(t *testing.T) {
	// Значение с ключом другого типа не должно читаться как userID.
	ctx := context.WithValue(context.Background(), otherKey{}, "intruder")
	_, err := FromContext(ctx)
	assert.Error(t, err)
}

func TestNewContext_Overrides(t *testing.T) {
	ctx := NewContext(NewContext(context.Background(), "a"), "b")
	id, err := FromContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "b", id)
}
