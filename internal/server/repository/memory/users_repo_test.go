package memory

import (
	"testing"

	"github.com/LifeforDream/pract-gophkeeper/internal/server/repository/repotest"
)

func TestUsersRepo_Contract(t *testing.T) {
	repotest.RunUsers(t, func(_ *testing.T) repotest.UsersRepo {
		return NewUsersRepo()
	})
}
