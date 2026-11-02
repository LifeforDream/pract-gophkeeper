package pbconv

import (
	"testing"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromProto(t *testing.T) {
	tests := []struct {
		name    string
		in      *pb.Argon2Params
		want    kdfparams.Params
		wantErr bool
	}{
		{"обычные значения", pb.Argon2Params_builder{MemoryKib: 64, Iterations: 3, Parallelism: 4}.Build(),
			kdfparams.Params{MemoryKiB: 64, Iterations: 3, Parallelism: 4}, false},
		{"parallelism 255 помещается в uint8", pb.Argon2Params_builder{Parallelism: 255}.Build(),
			kdfparams.Params{Parallelism: 255}, false},
		{"parallelism 256 не усекается", pb.Argon2Params_builder{Parallelism: 256}.Build(), kdfparams.Params{}, true},
		{"parallelism максимального uint32", pb.Argon2Params_builder{Parallelism: 1<<32 - 1}.Build(), kdfparams.Params{}, true},
		{"nil-сообщение даёт нулевые параметры", nil, kdfparams.Params{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromProto(tt.in)
			if tt.wantErr {
				require.ErrorIs(t, err, kdfparams.ErrInvalidParams)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestToProto_RoundTrip(t *testing.T) {
	p := kdfparams.DefaultParams()
	got, err := FromProto(ToProto(p))
	require.NoError(t, err)
	assert.Equal(t, p, got)
}
