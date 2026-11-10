package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/term"
)

// StdTerminal — реализация Terminal поверх os.Stdin, os.Stdout и os.Stderr.
// Приглашения к вводу печатаются в stderr, чтобы не попадать в перенаправленный stdout.
type StdTerminal struct {
	in        *os.File
	out       io.Writer
	err       io.Writer
	r         *bufio.Reader
	cancelled atomic.Bool // помогает защититься от гонок во время Ctrl+C.
}

// NewStdTerminal создаёт и возвращает терминал, привязанный к стандартным потокам процесса.
func NewStdTerminal() *StdTerminal {
	return &StdTerminal{
		in:  os.Stdin,
		out: os.Stdout,
		err: os.Stderr,
		r:   bufio.NewReader(os.Stdin),
	}
}

// Stderr возвращает поток для сообщений об ошибках и приглашений к вводу.
func (t *StdTerminal) Stderr() io.Writer {
	return t.err
}

// Stdout возвращает поток для результатов команд.
func (t *StdTerminal) Stdout() io.Writer {
	return t.out
}

// Stdin возвращает поток ввода.
func (t *StdTerminal) Stdin() io.Reader {
	return t.in
}

// Interactive сообщает, подключён ли стандартный ввод к терминалу, а не к каналу или файлу.
func (t *StdTerminal) Interactive() bool {
	return term.IsTerminal(int(t.in.Fd()))
}

// ReadLine печатает prompt и читает одну строку из стандартного ввода без завершающего
// перевода строки. Если ввод не терминал, строка читается без учёта ctx. Если ctx отменён
// раньше, чем введена строка, возвращает ctx.Err(); горутина чтения при этом остаётся
// заблокированной до завершения процесса, поэтому после отмены все последующие вызовы
// сразу возвращают ошибку.
func (t *StdTerminal) ReadLine(ctx context.Context, prompt string) (string, error) {
	if t.cancelled.Load() {
		return "", context.Canceled
	}
	fmt.Fprint(t.err, prompt)
	if !t.Interactive() {
		return readInputLine(t.r)
	}
	fd := int(t.in.Fd())
	old, err := term.GetState(fd)
	if err != nil {
		return "", err
	}
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() { line, err := readInputLine(t.r); ch <- res{line, err} }()
	var l string
	select {
	case r := <-ch:
		fmt.Fprintln(t.err)
		l, err = r.line, r.err
	case <-ctx.Done():
		t.cancelled.Store(true)
		_ = term.Restore(fd, old)
		l, err = "", ctx.Err()
	}

	return l, err
}

// ReadSecret печатает prompt и читает секрет. В интерактивном режиме вводимые символы
// не отображаются; если стандартный ввод не терминал, читается обычная строка.
// Вызывающий должен обнулить результат после использования. При отмене контекста
// возвращает ctx.Err() и восстанавливает состояние терминала (включает эхо); горутина
// чтения остаётся заблокированной до завершения процесса, поэтому после отмены все
// последующие вызовы сразу возвращают ошибку.
func (t *StdTerminal) ReadSecret(ctx context.Context, prompt string) ([]byte, error) {
	if t.cancelled.Load() {
		return nil, context.Canceled
	}
	fmt.Fprint(t.err, prompt)
	if !t.Interactive() {
		s, err := readInputLine(t.r)
		return []byte(s), err
	}
	fd := int(t.in.Fd())
	old, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { b, err := term.ReadPassword(fd); ch <- res{b, err} }()
	select {
	case r := <-ch:
		fmt.Fprintln(t.err)
		return r.b, r.err
	case <-ctx.Done():
		t.cancelled.Store(true)
		_ = term.Restore(fd, old)
		return nil, ctx.Err()
	}
}

func readInputLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) || line == "" {
			return "", err
		}
	}

	line = strings.TrimPrefix(line, "\uFEFF")
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}
