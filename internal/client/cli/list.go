package cli

import (
	"context"
	"flag"
	"fmt"
	"slices"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

// knownTypes - типы секретов, допустимые для --type.
var knownTypes = []domain.RecType{domain.TypeLogin, domain.TypeText, domain.TypeBinary, domain.TypeCard}

// cmdList ищет секреты на сервере по типу, ключу метаданных и фрагменту имени.
func (c *CLI) cmdList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())
	var typ, metaKey, name string
	fs.StringVar(&typ, "type", "", "only secrets of this type: login | text | binary | card")
	fs.StringVar(&metaKey, "meta-key", "", "only secrets that have this meta key (exact, case-sensitive)")
	fs.StringVar(&name, "name", "", "only secrets whose name contains this text (case-insensitive)")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper list [--type <type>] [--meta-key <key>] [--name <fragment>]\n\n")
		fmt.Fprint(out, "Lists your secrets without their content. Filters are optional and combined with AND.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}
	if fs.NArg() > 0 {
		return userInputError{fmt.Sprintf("unexpected argument %q, use --name to filter by name", fs.Arg(0))}
	}

	filter := domain.Filter{MetaKey: metaKey, NameFragment: name}
	if typ != "" {
		recType := domain.RecType(typ)
		if !slices.Contains(knownTypes, recType) {
			return userInputError{fmt.Sprintf("unknown secret type: %s", typ)}
		}
		filter.Type = recType
	}

	result, err := c.vault.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("error searching records: %w", err)
	}
	c.printItems(result)
	return nil
}
