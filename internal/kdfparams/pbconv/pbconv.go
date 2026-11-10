// Package pbconv преобразует параметры KDF между доменным типом kdfparams.Params и proto-моделью.
// Отдельный пакет нужен, чтобы kdfparams (а значит и client/crypto) не зависел от сгенерированного кода.
// Используется сервером (grpcsrv) и клиентом (transport).
package pbconv

import (
	"fmt"
	"math"

	pb "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
)

// FromProto собирает параметры из proto-модели.
// Если parallelism не помещается в uint8, возвращается kdfparams.ErrInvalidParams: молчаливого усечения нет.
// Границы значений здесь не проверяются, это делает Params.Validate.
func FromProto(params *pb.Argon2Params) (kdfparams.Params, error) {
	if params.GetParallelism() > math.MaxUint8 {
		return kdfparams.Params{}, fmt.Errorf("parallelism %d out of range: %w", params.GetParallelism(), kdfparams.ErrInvalidParams)
	}
	return kdfparams.Params{
		MemoryKiB:   params.GetMemoryKib(),
		Iterations:  params.GetIterations(),
		Parallelism: uint8(params.GetParallelism()),
	}, nil
}

// ToProto превращает параметры в proto-модель.
func ToProto(p kdfparams.Params) *pb.Argon2Params {
	return pb.Argon2Params_builder{
		MemoryKib:   p.MemoryKiB,
		Parallelism: uint32(p.Parallelism),
		Iterations:  p.Iterations,
	}.Build()
}
