package kdfparams

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testParams — дешёвые параметры Argon2id, чтобы тесты работали быстро.
// Память равна нижнему допустимому пределу.
var testParams = Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}

func TestDefaultParams_Valid(t *testing.T) {
	assert.NoError(t, DefaultParams().Validate())
}

func TestParams_Validate(t *testing.T) {
	tests := []struct {
		name    string
		params  Params
		wantErr bool
	}{
		{"default", DefaultParams(), false},
		{"test params", testParams, false},
		{"memory at lower limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 1}, false},
		{"memory at upper limit", Params{MemoryKiB: MemoryUpperLimitKib, Iterations: 1, Parallelism: 1}, false},
		{"memory below lower limit", Params{MemoryKiB: MemoryLowerLimitKiB - 1, Iterations: 1, Parallelism: 1}, true},
		{"memory zero", Params{MemoryKiB: 0, Iterations: 1, Parallelism: 1}, true},
		{"memory above upper limit", Params{MemoryKiB: MemoryUpperLimitKib + 1, Iterations: 1, Parallelism: 1}, true},
		{"zero iterations", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 0, Parallelism: 1}, true},
		{"iterations at upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: IterationsUpperLimit, Parallelism: 1}, false},
		{"iterations above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: IterationsUpperLimit + 1, Parallelism: 1}, true},
		{"zero parallelism", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: 0}, true},
		{"parallelism at upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: ParallelismUpperLimit}, false},
		{"parallelism above upper limit", Params{MemoryKiB: MemoryLowerLimitKiB, Iterations: 1, Parallelism: ParallelismUpperLimit + 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidParams)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestNewSalt(t *testing.T) {
	a, err := NewSalt()
	require.NoError(t, err)
	b, err := NewSalt()
	require.NoError(t, err)

	assert.Len(t, a, SaltSize)
	assert.Len(t, b, SaltSize)
	assert.NotEqual(t, a, b, "две соли подряд не должны совпадать")
}
