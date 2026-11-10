package memory

import (
	"testing"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/repotest"
)

func TestRecordsRepo_Contract(t *testing.T) {
	repotest.RunRecords(t, func(_ *testing.T) repotest.RecordsRepo {
		return NewRecordsRepo()
	})
}
