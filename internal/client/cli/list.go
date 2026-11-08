package cli

import (
	"context"
	"flag"
	"fmt"
)

func (c *CLI) cmdList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper list\n\n")
		fmt.Fprint(out, "Lists your secrets without their content.\n")
	}
	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}

	result, err := c.vault.List(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving list of records: %w", err)
	}

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
	return nil
}
