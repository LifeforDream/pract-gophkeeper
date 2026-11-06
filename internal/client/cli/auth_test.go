package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogin(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		env         string
		interactive bool
		lines       []string
		secrets     []string
		wantLogin   string
		wantPw      string
		wantCode    int
		wantCalls   int
	}{
		{"flag and prompted password", []string{"login", "--login", "bob"}, "", true, nil, []string{"pw"}, "bob", "pw", 0, 1},
		{"password from env", []string{"login", "--login", "bob"}, "envpw", true, nil, nil, "bob", "envpw", 0, 1},
		{"login prompted when tty", []string{"login"}, "", true, []string{"alice"}, []string{"pw"}, "alice", "pw", 0, 1},
		{"no login and no tty", []string{"login"}, "envpw", false, nil, nil, "", "", 2, 0},
		{"password prompt hits EOF", []string{"login", "--login", "bob"}, "", true, nil, nil, "", "", 2, 0},
		{"unknown flag", []string{"login", "--nope"}, "", true, nil, nil, "", "", 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			t.Setenv("GOPHKEEPER_PASSWORD", tt.env)
			h.term.interactive, h.term.lines, h.term.secrets = tt.interactive, tt.lines, tt.secrets

			code := h.run(tt.args...)

			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantCalls, h.auth.loginCalls)
			assert.Equal(t, tt.wantLogin, h.auth.login)
			assert.Equal(t, tt.wantPw, h.auth.password)
		})
	}
}

// TestAuth_ErrorPropagates проверяет, что ошибка app-слоя доходит до кода выхода в каждой команде.
func TestAuth_ErrorPropagates(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		secrets []string
	}{
		{"login", []string{"login", "--login", "bob"}, []string{"pw"}},
		{"register", []string{"register", "--login", "bob"}, []string{"pw", "pw"}},
		{"logout", []string{"logout"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.auth.err = errBoom
			h.term.secrets = tt.secrets

			assert.Equal(t, 1, h.run(tt.args...))
		})
	}
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		lines     []string
		secrets   []string
		wantCode  int
		wantCalls int
		wantLogin string
	}{
		{"passwords match", []string{"register", "--login", "bob"}, nil, []string{"pw", "pw"}, 0, 1, "bob"},
		{"passwords differ", []string{"register", "--login", "bob"}, nil, []string{"pw", "other"}, 2, 0, ""},
		{"login prompted", []string{"register"}, []string{"alice"}, []string{"pw", "pw"}, 0, 1, "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.term.lines, h.term.secrets = tt.lines, tt.secrets

			assert.Equal(t, tt.wantCode, h.run(tt.args...))
			assert.Equal(t, tt.wantCalls, h.auth.registerCalls, "регистрация требует двойного ввода пароля")
			assert.Equal(t, tt.wantLogin, h.auth.login)
		})
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		code  int
		calls int
	}{
		{"removes session", []string{"logout"}, 0, 1},
		{"unknown flag", []string{"logout", "--nope"}, 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)

			assert.Equal(t, tt.code, h.run(tt.args...))
			assert.Equal(t, tt.calls, h.auth.logoutCalls)
		})
	}
}
