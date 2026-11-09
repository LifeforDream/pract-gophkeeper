// Package cli хранит реализацию работы с cli с app.
package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

// Authenticator описывает необходимые для аутентификации методы app.
type Authenticator interface {
	Register(ctx context.Context, login string, password []byte) error
	Login(ctx context.Context, login string, password []byte) error
	Logout() error
}

// Vault описывает необходимые для работы с хранилищем методы приложения.
type Vault interface {
	Add(ctx context.Context, s domain.Secret) (id string, warnings []string, err error)
	ListChanges(ctx context.Context, ro app.ReadOptions) (app.ListResult, error)
	List(ctx context.Context, filter domain.Filter, ro app.ReadOptions) (app.ListResult, error)
	Get(ctx context.Context, ref string, ro app.ReadOptions) (app.Entry, error)
	Update(ctx context.Context, id string, expectedVersion int64, s domain.Secret) (warnings []string, err error)
	Delete(ctx context.Context, ref string) (warnings []string, err error)
}

// Terminal описывает необходимые методы от терминала.
type Terminal interface {
	Stdout() io.Writer
	Stderr() io.Writer
	Interactive() bool
	ReadLine(ctx context.Context, prompt string) (string, error)
	ReadSecret(ctx context.Context, prompt string) ([]byte, error)
}

// stringSlice — повторяемый строковый флаг: каждое его появление в командной строке
// добавляет значение в срез. Реализует flag.Value.
type stringSlice []string

// String возвращает значения флага через запятую. Нужен для интерфейса flag.Value.
func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

// Set добавляет очередное значение флага в срез. Никогда не возвращает ошибку.
// Нужен для интерфейса flag.Value.
func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// userInputError - обёртка над ошибкой пользовательского ввода.
type userInputError struct {
	message string
}

// Error позволяет использовать userInputError как ошибку.
func (u userInputError) Error() string {
	return fmt.Sprintf("user input error: %s", u.message)
}

// commandHelp описывает одну команду в общей справке.
type commandHelp struct {
	name string
	desc string
}

// commandsHelp возвращает команды в порядке показа в справке.
// Порядок задан срезом, потому что обход map случаен.
func commandsHelp() []commandHelp {
	return []commandHelp{
		{"register", "create a new account"},
		{"login", "sign in and store a session"},
		{"logout", "remove the stored session"},
		{"add", "add a secret: login | text | binary | card"},
		{"list", "search secrets by --type, --meta-key, --name (names, types, ids)"},
		{"sync", "update the local cache and list all secrets (names, types, ids)"},
		{"get", "show a secret by id or name"},
		{"update", "change a secret by id or name"},
		{"delete", "delete a secret by id or name"},
		{"version", "print the client version"},
	}
}

// PrintUsage печатает общую справку в w.
func PrintUsage(w io.Writer) {
	fmt.Fprint(w, "GophKeeper - password manager client\n\n")
	fmt.Fprint(w, "Usage:\n  gophkeeper [global options] <command> [arguments]\n\n")
	fmt.Fprint(w, "Commands:\n")

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, h := range commandsHelp() {
		fmt.Fprintf(tw, "  %s\t%s\n", h.name, h.desc)
	}
	_ = tw.Flush()

	fmt.Fprint(w, "\nEnvironment:\n  GOPHKEEPER_PASSWORD   password for scripts; if unset, you are prompted\n")
	fmt.Fprint(w, "\nRun \"gophkeeper <command> -h\" for help on a command.\n")
}

// printUsage печатает общую справку в w.
func (c *CLI) printUsage(w io.Writer) {
	PrintUsage(w)
	if c.globalHelp != nil {
		c.globalHelp(w)
	}
}

// Option настраивает CLI при создании.
type Option func(*CLI)

// WithGlobalOptionsHelp задаёт функцию, печатающую описание глобальных флагов
// в общей справке. Флаги принадлежат вызывающему коду, поэтому CLI их не знает.
func WithGlobalOptionsHelp(f func(io.Writer)) Option {
	return func(c *CLI) { c.globalHelp = f }
}

// CLI хранит данные для работы с терминалом в CLI-режиме.
type CLI struct {
	auth       Authenticator
	vault      Vault
	term       Terminal
	commands   map[string]command
	globalHelp func(io.Writer)
}

// New возвращает готовый к работе CLI.
func New(auth Authenticator, vault Vault, term Terminal, opts ...Option) *CLI {
	c := &CLI{
		auth:  auth,
		vault: vault,
		term:  term,
	}
	c.commands = map[string]command{
		"add":      c.cmdAdd,
		"list":     c.cmdList,
		"sync":     c.cmdSync,
		"get":      c.cmdGet,
		"update":   c.cmdUpdate,
		"delete":   c.cmdDelete,
		"register": c.cmdRegister,
		"login":    c.cmdLogin,
		"logout":   c.cmdLogout,
		"version":  c.cmdVersion,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// command — обработчик одной подкоманды. Получает аргументы после имени команды
// и возвращает ошибку, которую Run превращает в сообщение и код выхода.
type command func(context.Context, []string) error

// Run запускает команду, выбирая по аргументам. Возвращает код ошибки.
// Никогда не вызывает os.Exit.
func (c *CLI) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		c.printUsage(c.term.Stdout())
		return 2
	}
	switch args[0] {
	case "help", "--help":
		c.printUsage(c.term.Stdout())
		return 0
	}
	command, ok := c.commands[args[0]]
	if !ok {
		fmt.Fprintf(c.term.Stderr(), "unknown command: %s\n", args[0])
		c.printUsage(c.term.Stderr())
		return 2
	}
	err := command(ctx, args[1:])
	if err != nil {
		text, code := renderError(err)
		fmt.Fprintf(c.term.Stderr(), "%s\n", text)
		return code
	}
	return 0
}

// cmdVersion ничего не делает, поскольку версия печатается при вызове CLI всегда.
func (c *CLI) cmdVersion(_ context.Context, _ []string) error {
	return nil
}

// warn печатает предупреждения в stderr.
func (c *CLI) warn(warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(c.term.Stderr(), "warning: %s\n", w)
	}
}

// warnStale предупреждает, что данные взяты из кэша и могут быть устаревшими.
func (c *CLI) warnStale(stale, offline bool) {
	switch {
	case !stale:
	case offline:
		fmt.Fprint(c.term.Stderr(), "warning: offline mode, showing cached data\n")
	default:
		fmt.Fprint(c.term.Stderr(), "warning: server is unreachable, showing cached data\n")
	}
}

// formatMeta форматирует метаданные в виде "k=v k=v" — тот же формат принимает splitMeta.
func formatMeta(meta []domain.MetaItem) string {
	parts := make([]string, 0, len(meta))
	for _, m := range meta {
		parts = append(parts, m.Key+"="+m.Value)
	}
	return strings.Join(parts, " ")
}
