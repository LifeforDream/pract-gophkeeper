package domain

import "errors"

var (
	// ErrConflict - данные на сервере были обновлены другим клиентом.
	ErrConflict = errors.New("conflict on server")
	// ErrNotFound - запись не найдена.
	ErrNotFound = errors.New("not found")
	// ErrLoginTaken - логин уже занят. Можно получить при Register.
	ErrLoginTaken = errors.New("login taken")
	// ErrInvalidCredentials - при Login не подошёл логин или пароль.
	ErrInvalidCredentials = errors.New("credentials are invalid")
	// ErrSessionExpired - у токена истёк ttl.
	ErrSessionExpired = errors.New("session is expired")
	// ErrTooLarge - в Header или Content был отправлен слишком большой файл.
	ErrTooLarge = errors.New("payload is too large")
	// ErrNoSession - была попытка обратиться к серверу без токена.
	ErrNoSession = errors.New("no session present")
	// ErrServerMismatch - была попытка получить данные с неправильного сервера.
	ErrServerMismatch = errors.New("wrong server")
	// ErrInvalidData означает, что запись некорректна.
	ErrInvalidData = errors.New("invalid data")
	// ErrUnavailable - сервер недоступен на уровне сети (UNAVAILABLE, DEADLINE_EXCEEDED).
	ErrUnavailable = errors.New("server is unavailable")
	// ErrBodyNotCached - тела записи нет в локальном кэше, а сервер недоступен или не опрашивается.
	ErrBodyNotCached = errors.New("body is not cached")
	// ErrServerReset - ревизия сервера ниже закэшированной: сервер был сброшен, кэш нужно пересобрать.
	ErrServerReset = errors.New("server revision is lower than cached")
)
