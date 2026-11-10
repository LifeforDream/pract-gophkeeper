package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LifeforDream/pract-gophkeeper/internal/client/domain"
)

func (c *CLI) cmdAdd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return userInputError{"missing type argument"}
	}
	secretType := args[0]

	var metaFlag stringSlice

	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(c.term.Stderr())

	nameFlag := fs.String("name", "", "name of the secret")

	fs.Var(&metaFlag, "meta", "repeated meta flag in the form of meta k=v")

	fileFlag := fs.String("file", "", "filepath to a file with secret. Relevant for binary type")

	if err := fs.Parse(args[1:]); err != nil {
		// Parse уже распечатал ошибку и Usage
		return userInputError{"see above"}
	}

	if *nameFlag == "" {
		return userInputError{"empty secret name is not allowed"}
	}

	// проверим, существует ли файл
	if secretType == "binary" {
		if *fileFlag == "" {
			return userInputError{"binary add requires valid --file"}
		}
	}

	meta, err := splitMeta(metaFlag)
	if err != nil {
		return fmt.Errorf("error parsing meta flag: %w", err)
	}

	var id string
	var innerErr error
	switch secretType {
	case "login":
		id, innerErr = c.addLogin(ctx, *nameFlag, meta)
	case "text":
		id, innerErr = c.addText(ctx, *nameFlag, meta)
	case "binary":
		id, innerErr = c.addBinary(ctx, *nameFlag, *fileFlag, meta)
	case "card":
		id, innerErr = c.addCard(ctx, *nameFlag, meta)
	default:
		return userInputError{fmt.Sprintf("unknown secret type: %s", secretType)}
	}
	if innerErr != nil {
		return fmt.Errorf("error adding record: %w", innerErr)
	}
	fmt.Fprintf(c.term.Stdout(), "record %s added with id %s\n", *nameFlag, id)
	return nil
}

func (c *CLI) addLogin(ctx context.Context, name string, meta []domain.MetaItem) (string, error) {
	login, err := c.term.ReadLine(ctx, "Login: ")
	if err != nil {
		return "", fmt.Errorf("error reading login for login: %w", err)
	}

	pw, err := c.term.ReadSecret(ctx, "Password: ")
	if err != nil {
		return "", fmt.Errorf("error reading password for login: %w", err)
	}
	defer clear(pw)

	sec := domain.Secret{
		Type:    domain.TypeLogin,
		Name:    name,
		Meta:    meta,
		Content: domain.Login{Username: login, Password: string(pw)},
	}

	id, warnings, err := c.vault.Add(ctx, sec)
	if err != nil {
		return "", fmt.Errorf("error adding login on server: %w", err)
	}
	c.warn(warnings)

	return id, nil
}

func (c *CLI) addText(ctx context.Context, name string, meta []domain.MetaItem) (string, error) {
	text, err := c.term.ReadLine(ctx, "Your text: ")
	if err != nil {
		return "", fmt.Errorf("error reading text for add text: %w", err)
	}

	sec := domain.Secret{
		Type:    domain.TypeText,
		Name:    name,
		Meta:    meta,
		Content: domain.Text(text),
	}
	id, warnings, err := c.vault.Add(ctx, sec)
	if err != nil {
		return "", fmt.Errorf("error adding text on server: %w", err)
	}
	c.warn(warnings)

	return id, nil
}

func (c *CLI) addBinary(ctx context.Context, name, fp string, meta []domain.MetaItem) (string, error) {
	data, err := os.ReadFile(fp)
	if err != nil {
		return "", fmt.Errorf("error reading file for record sending: %w", err)
	}

	sec := domain.Secret{
		Type: domain.TypeBinary,
		Name: name,
		Meta: meta,
		Content: domain.Binary{
			Filename: filepath.Base(fp),
			Data:     data,
		},
	}
	id, warnings, err := c.vault.Add(ctx, sec)
	if err != nil {
		return "", fmt.Errorf("error adding binary data on server: %w", err)
	}
	c.warn(warnings)

	return id, nil
}

func (c *CLI) addCard(ctx context.Context, name string, meta []domain.MetaItem) (string, error) {
	number, err := c.term.ReadSecret(ctx, "Number: ")
	if err != nil {
		return "", fmt.Errorf("error reading number for card: %w", err)
	}

	defer clear(number)

	holder, err := c.term.ReadLine(ctx, "Holder: ")
	if err != nil {
		return "", fmt.Errorf("error reading holder for card: %w", err)
	}

	expiry, err := c.term.ReadLine(ctx, "Expiry: ")
	if err != nil {
		return "", fmt.Errorf("error reading expiry for card: %w", err)
	}

	cvv, err := c.term.ReadSecret(ctx, "CVV: ")
	if err != nil {
		return "", fmt.Errorf("error reading cvv for card: %w", err)
	}

	defer clear(cvv)

	sec := domain.Secret{
		Type: domain.TypeCard,
		Name: name,
		Meta: meta,
		Content: domain.Card{
			Number: string(number),
			Holder: holder,
			Expiry: expiry,
			CVV:    string(cvv),
		},
	}

	id, warnings, err := c.vault.Add(ctx, sec)
	if err != nil {
		return "", fmt.Errorf("error adding card on server: %w", err)
	}
	c.warn(warnings)

	return id, nil
}

func splitMeta(meta stringSlice) ([]domain.MetaItem, error) {
	items := make([]domain.MetaItem, 0, len(meta))
	for _, m := range meta {
		k, v, ok := strings.Cut(m, "=")
		if !ok || k == "" {
			return nil, userInputError{fmt.Sprintf("invalid meta %q, expected key=value", m)}
		}
		items = append(items, domain.MetaItem{Key: k, Value: v})
	}
	return items, nil
}
