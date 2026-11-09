package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/app"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func (c *CLI) cmdUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, "Usage:\n  gophkeeper update <id|name>\n\n")
		fmt.Fprint(out, "Starts secret update sequence.\n")
		fmt.Fprint(out, "If the secret is found, you will be prompted with new values according to its type.\n\n")
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

	entry, err := c.vault.Get(ctx, ref, app.ReadOptions{RequireOnline: true})
	if err != nil {
		return fmt.Errorf("error retrieving existing record for update: %w", err)
	}
	fmt.Fprintf(c.term.Stdout(), "What would you like to change? \n")

	newEntry := entry

	newName, err := c.term.ReadLine(ctx, fmt.Sprintf("Name (default %s): ", entry.Header.Name))
	if err != nil {
		return fmt.Errorf("error reading value for new name: %w", err)
	}
	if newName == "" {
		newName = entry.Header.Name
	}

	var metaItems []domain.MetaItem

	metaIn, err := c.term.ReadLine(ctx, fmt.Sprintf("Meta in the form of foo=bar baz=qux  (default %q): ", formatMeta(entry.Header.Meta)))
	if err != nil {
		return fmt.Errorf("error reading new value for meta: %w", err)
	}
	if metaIn == "" {
		metaItems = entry.Header.Meta
	} else {
		metaItems, err = splitMeta(stringSlice(strings.Split(metaIn, " ")))
		if err != nil {
			return fmt.Errorf("error parsing meta in update: %w", err)
		}
	}

	hd := domain.Header{
		Type: entry.Header.Type,
		Name: newName,
		Meta: metaItems,
	}

	newEntry.Header = hd
	newEntry.Secret.Header = hd

	switch entry.Header.Type {
	case domain.TypeLogin:
		err = c.updateLogin(ctx, &entry, &newEntry)
	case domain.TypeText:
		err = c.updateText(ctx, &entry, &newEntry)
	case domain.TypeBinary:
		err = c.updateBinary(ctx, &entry, &newEntry)
	case domain.TypeCard:
		err = c.updateCard(ctx, &entry, &newEntry)
	default:
		return userInputError{fmt.Sprintf("unexpected type %s", entry.Header.Type)}
	}
	if err != nil {
		return fmt.Errorf("error updating details on record %s: %w", newEntry.Header.Name, err)
	}

	warnings, err := c.vault.Update(ctx, newEntry.ID, newEntry.Version, newEntry.Secret)
	if err != nil {
		return fmt.Errorf("error updating record on server: %w", err)
	}
	c.warn(warnings)
	fmt.Fprintf(c.term.Stdout(), "successfully updated record %s\n", newEntry.ID)
	return nil
}

func (c *CLI) updateLogin(ctx context.Context, oldEntry, newEntry *app.Entry) error {
	content, ok := oldEntry.Secret.Content.(domain.Login)
	if !ok {
		return userInputError{"secret is not login"}
	}
	login, err := c.term.ReadLine(ctx, fmt.Sprintf("New login (default %s): ", content.Username))
	if err != nil {
		return fmt.Errorf("error reading login for update login: %w", err)
	}

	if login == "" {
		login = content.Username
	}

	pw, err := c.term.ReadSecret(ctx, "Password: (empty = keep previous) ")
	if err != nil {
		return fmt.Errorf("error reading password for update login: %w", err)
	}

	defer clear(pw)

	password := string(pw)
	if password == "" {
		password = content.Password
	}
	newEntry.Secret.Content = domain.Login{Username: login, Password: password}
	return nil
}

func (c *CLI) updateText(ctx context.Context, oldEntry, newEntry *app.Entry) error {
	content, ok := oldEntry.Secret.Content.(domain.Text)
	if !ok {
		return userInputError{"secret is not text"}
	}

	// text не слишком секретный, можно и напечатать в терминале
	text, err := c.term.ReadLine(ctx, fmt.Sprintf("Enter next text (default: \n %s): ", content))
	if err != nil {
		return fmt.Errorf("error reading text for update text: %w", err)
	}

	if !(text == "") {
		newEntry.Secret.Content = domain.Text(text)
	}
	return nil
}

func (c *CLI) updateBinary(ctx context.Context, oldEntry, newEntry *app.Entry) error {
	_, ok := oldEntry.Secret.Content.(domain.Binary)
	if !ok {
		return userInputError{"secret is not binary data"}
	}

	fp, err := c.term.ReadLine(ctx, "Enter path to file (empty = keep previous): ")
	if err != nil {
		return fmt.Errorf("error reading filepath for update binary: %w", err)
	}
	if fp == "" {
		// не нужно заново загружать файл.
		return nil
	}

	data, err := os.ReadFile(fp)
	if err != nil {
		return fmt.Errorf("error reading file %s for updating binary: %w", fp, err)
	}

	newEntry.Secret.Content = domain.Binary{Filename: filepath.Base(fp), Data: data}
	return nil
}

func (c *CLI) updateCard(ctx context.Context, oldEntry, newEntry *app.Entry) error {
	content, ok := oldEntry.Secret.Content.(domain.Card)
	if !ok {
		return userInputError{"secret is not card details"}
	}

	var numberStr string
	number, err := c.term.ReadSecret(ctx, fmt.Sprintf("Enter new card number (default: %s): ", maskCardNumber(content.Number)))
	if err != nil {
		return fmt.Errorf("error reading new card number: %w", err)
	}
	if len(number) == 0 {
		numberStr = content.Number
	} else {
		numberStr = string(number)
		defer clear(number)
	}

	holder, err := c.term.ReadLine(ctx, fmt.Sprintf("Enter new holder (default: %s): ", content.Holder))
	if err != nil {
		return fmt.Errorf("error reading new holder: %w", err)
	}
	if holder == "" {
		holder = content.Holder
	}

	expiry, err := c.term.ReadLine(ctx, fmt.Sprintf("Enter new expiry date (default: %s): ", content.Expiry))
	if err != nil {
		return fmt.Errorf("error reading new expiry date: %w", err)
	}
	if expiry == "" {
		expiry = content.Expiry
	}

	var cvvStr string
	cvv, err := c.term.ReadSecret(ctx, "Enter new CVV (default is to leave previous values): ")
	if err != nil {
		return fmt.Errorf("error reading new CVV: %w", err)
	}
	if len(cvv) == 0 {
		cvvStr = content.CVV
	} else {
		cvvStr = string(cvv)
		defer clear(cvv)
	}

	newEntry.Secret.Content = domain.Card{
		Number: numberStr,
		Holder: holder,
		Expiry: expiry,
		CVV:    cvvStr,
	}
	return nil
}
