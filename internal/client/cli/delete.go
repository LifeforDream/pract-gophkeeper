package cli

import (
	"context"
	"flag"
	"fmt"
	"slices"
)

var affirmatives = []string{"y", "Y", "yes", "YES"}

func (c *CLI) cmdDelete(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	yesFlag := fs.Bool("yes", false, "skip confirmation prompt")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper delete [options] <id|name>\n\n")
		fmt.Fprint(out, "Deletes a secret after confirmation.\n")
		fmt.Fprint(out, "If the name matches several secrets, use the id.\n")
		fmt.Fprint(out, "Options: \n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return userInputError{"no record reference provided"}
	}
	ref := fs.Arg(0)

	entry, err := c.vault.Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("error retrieving existing record for delete: %w", err)
	}

	if !*yesFlag {
		resp, err := c.term.ReadLine(ctx, fmt.Sprintf("Are you sure you want to delete record %s - %s? (y/n): ", entry.ID, entry.Header.Name))
		if err != nil {
			return fmt.Errorf("error reading deletion confirmation: %w", err)
		}
		if resp == "" || !slices.Contains(affirmatives, resp) {
			fmt.Fprint(c.term.Stdout(), "Cancelling operation\n")
			return nil
		}
	}

	err = c.vault.Delete(ctx, entry.ID)
	if err != nil {
		return fmt.Errorf("error deleting record %s on server: %w", ref, err)
	}
	fmt.Fprintf(c.term.Stdout(), "successfully deleted record %s\n", entry.ID)
	return nil
}
