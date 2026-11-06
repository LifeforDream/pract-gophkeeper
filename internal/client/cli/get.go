package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func (c *CLI) cmdGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	showFlag := fs.Bool("show", false, "to show sensitive secrets")
	outFlag := fs.String("out", "", "name of the file to write when a binary data is requested. If not provided for binary, no file would be written.")
	forceFlag := fs.Bool("force", false, "overwrite file if it exists")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper get <id|name> [options]\n\n")
		fmt.Fprint(out, "Shows a secret. Passwords, card numbers and CVV are masked unless --show is set.\n")
		fmt.Fprint(out, "If the name matches several secrets, use the id.\n\n")
		fmt.Fprint(out, "Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return userInputError{"invalid reference"}
	}
	ref := fs.Arg(0)

	entry, err := c.vault.Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("error getting record from server: %w", err)
	}

	fmt.Fprintf(c.term.Stdout(), "Secret id: %s, name: %s, type: %s, version: %d \n", entry.ID, entry.Header.Name, entry.Header.Type, entry.Version)
	fmt.Fprintf(c.term.Stdout(), "Secret meta: %q\n", formatMeta(entry.Header.Meta))

	switch v := entry.Secret.Content.(type) {
	case domain.Login:
		fmt.Fprintf(c.term.Stdout(), "Login: %s\n", v.Username)
		password := maskPassword()
		if *showFlag {
			password = v.Password
		}
		fmt.Fprintf(c.term.Stdout(), "Password: %s\n", password)
	case domain.Text:
		fmt.Fprintf(c.term.Stdout(), "Text: %s\n", v)
	case domain.Binary:
		if *outFlag == "" {
			fmt.Fprintf(c.term.Stdout(), "File name: %s\n", v.Filename)
			fmt.Fprintf(c.term.Stdout(), "File size: %d\n", len(v.Data))
		} else {
			// проверим, существует ли файл
			var flags int
			if *forceFlag {
				flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
			} else {
				flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
			}
			f, err := os.OpenFile(*outFlag, flags, 0o600)
			if err != nil {
				if os.IsExist(err) {
					return userInputError{"file already exists"}
				}
				return fmt.Errorf("unexpected error opening file: %w", err)
			}
			_, err = f.Write(v.Data)
			if err != nil {
				if err = f.Close(); err != nil {
					return fmt.Errorf("error closing file: %w", err)
				}
				return fmt.Errorf("error writing file from server: %w", err)
			}

			fmt.Fprintf(c.term.Stdout(), "Wrote secret to file: %s\n", *outFlag)
			if err = f.Close(); err != nil {
				return fmt.Errorf("error closing file: %w", err)
			}
		}
	case domain.Card:
		number := maskCardNumber(v.Number)
		cvv := maskCVV()
		if *showFlag {
			number = v.Number
			cvv = v.CVV
		}
		fmt.Fprintf(c.term.Stdout(), "Card Number: %s\n", number)
		fmt.Fprintf(c.term.Stdout(), "Card Holder: %s\n", v.Holder)
		fmt.Fprintf(c.term.Stdout(), "Card Expiry: %s\n", v.Expiry)
		fmt.Fprintf(c.term.Stdout(), "Card CVV: %s\n", cvv)
	default:
		fmt.Fprintf(c.term.Stderr(), "Unformattable secret type\n")
	}
	return nil
}
