// Package domain содержит модели домена.
package domain

import (
	"time"

	"github.com/LifeforDream/pract-gophkeeper/internal/kdfparams"
)

// User - репрезентация пользователя.
type User struct {
	ID        string           // ID пользователя
	Login     string           // логин пользователя
	AuthHash  []byte           // хэш от auth_key пользователя
	KDFSalt   []byte           // "соль", переданная с клиента
	KDFParams kdfparams.Params // параметры шифрования пользователя
	CreatedAt time.Time        // дата создания пользователя с временем
}

// Record - экземпляр записи с секретом.
type Record struct {
	UserID      string    // ссылка на пользователя, которому принадлежит запись
	ID          string    // ID записи
	Version     int64     // версия записи
	Revision    int64     // ревизия, в которой запись обновлялась в последний раз
	Deleted     bool      // признак удаления записи
	Header      []byte    // зашифрованный заголовок
	HeaderNonce []byte    // nonce зашифрованного заголовка
	Body        []byte    // зашифрованное тело записи
	BodyNonce   []byte    // nonce зашифрованного тела записи
	UpdatedAt   time.Time // дата и время последнего обновления записи
}
