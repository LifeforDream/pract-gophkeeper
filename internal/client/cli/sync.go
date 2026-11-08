package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
)

// cmdSync выводит все секреты пользователя без содержимого (ListChanges с нуля).
func (c *CLI) cmdSync(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper sync\n\n")
		fmt.Fprint(out, "Fetches all your secrets from the server and lists them without their content.\n")
	}
	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}

	result, err := c.vault.ListChanges(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving list of records: %w", err)
	}
	c.printItems(result)
	return nil
}

// printItems печатает список секретов. Общий вывод для list и sync.
func (c *CLI) printItems(result app.ListResult) {
	fmt.Fprint(c.term.Stdout(), "Found Items: \n")
	for i, record := range result.Items {
		fmt.Fprintf(c.term.Stdout(),
			"%d. id: %s | name: %s | type: %s | version: %d \n",
			i+1,
			record.ID,
			record.Header.Name,
			record.Header.Type,
			record.Version,
		)
	}
}
