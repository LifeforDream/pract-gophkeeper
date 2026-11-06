package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
)

func (c *CLI) cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())
	loginFlag := fs.String("login", "", "account login")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper login [options]\n\n")
		fmt.Fprint(out, "Prompts for password, unless env GOPHKEEPER_PASSWORD is set.\n")
		fmt.Fprint(out, "Creates session locally.\n\n")
		fmt.Fprint(out, "Options:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	login := *loginFlag
	if login == "" {
		if !c.term.Interactive() {
			return userInputError{"--login is required when stdin is not a terminal"}
		}
		var err error
		if login, err = c.term.ReadLine(ctx, "Login: "); err != nil {
			return err
		}
	}

	pw, err := c.password(ctx, false)
	if err != nil {
		return err
	}
	defer clear(pw)

	return c.auth.Login(ctx, login, pw)
}

// password возвращает пароль пользователя. Если задана переменная окружения
// GOPHKEEPER_PASSWORD, берёт значение из неё (для скриптов), иначе запрашивает
// ввод без echo. При confirm = true просит ввести пароль повторно и возвращает
// ошибку, если значения не совпали.
func (c *CLI) password(ctx context.Context, confirm bool) ([]byte, error) {
	if v := os.Getenv("GOPHKEEPER_PASSWORD"); v != "" {
		return []byte(v), nil
	}
	pw, err := c.term.ReadSecret(ctx, "Password: ")
	if err != nil {
		return nil, fmt.Errorf("error reading password: %w", err)
	}
	if confirm {
		pw2, err := c.term.ReadSecret(ctx, "Confirm password: ")
		if err != nil {
			return nil, fmt.Errorf("error reading password confirmation: %w", err)
		}
		if slices.Compare(pw, pw2) != 0 {
			return nil, userInputError{"passwords are different"}
		}
	}
	return pw, nil
}

func (c *CLI) cmdRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	loginFlag := fs.String("login", "", "account login")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper register [options]\n\n")
		fmt.Fprint(out, "Prompts for password, unless env GOPHKEEPER_PASSWORD is set.\n")
		fmt.Fprint(out, "Creates session locally.\n\n")
		fmt.Fprint(out, "Options:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}
	login := *loginFlag
	if login == "" {
		if !c.term.Interactive() {
			return userInputError{"--login is required when stdin is not a terminal"}
		}
		var err error
		if login, err = c.term.ReadLine(ctx, "Login: "); err != nil {
			return err
		}
	}

	pw, err := c.password(ctx, true)
	if err != nil {
		return err
	}
	defer clear(pw)

	return c.auth.Register(ctx, login, pw)
}

func (c *CLI) cmdLogout(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper logout [options]\n\n")
		fmt.Fprint(out, "Deletes local session file.\n\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	return c.auth.Logout()
}
