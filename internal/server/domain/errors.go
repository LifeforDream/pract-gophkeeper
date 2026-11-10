package domain

import "errors"

var (
	// ErrLoginTaken получается при попытке зарегистрировать пользователя с дубликатом логина.
	ErrLoginTaken = errors.New("login already in use")
	// ErrBadCredentials получается при неверном логине или authKey.
	ErrBadCredentials = errors.New("invalid credentials")
	// ErrStaleVersion получается при попытке обновить или удалить запись, отправив устаревшую версию.
	ErrStaleVersion = errors.New("version too old")
	// ErrNotFound получается при попытке получить несуществующие данные.
	ErrNotFound = errors.New("not found")
	// ErrPayloadTooLarge получается при попытке отправить данные, превышающие лимиты сервера.
	ErrPayloadTooLarge = errors.New("payload too large")
	// ErrNoUserID получается при попытке получить данные, не передав userID.
	ErrNoUserID = errors.New("no user id in context")
	// ErrConflict получается при попытке произвести некорректную операцию над данными.
	ErrConflict = errors.New("there is conflict in data")
	// ErrInvalidArgument получается при неправильной передаче аргументов операции.
	ErrInvalidArgument = errors.New("invalid argument")
)
