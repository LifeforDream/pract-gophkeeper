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

// RecordType - тип записи. Сервер хранит его в открытом виде, чтобы в будущем уметь искать по нему.
type RecordType string

const (
	// TypeLogin - пара логин-пароль.
	TypeLogin RecordType = "login"
	// TypeText - произвольный текст.
	TypeText RecordType = "text"
	// TypeBinary - бинарные данные.
	TypeBinary RecordType = "binary"
	// TypeCard - данные банковской карты.
	TypeCard RecordType = "card"
)

// Valid сообщает, известен ли серверу тип записи.
func (t RecordType) Valid() bool {
	switch t {
	case TypeLogin, TypeText, TypeBinary, TypeCard:
		return true
	}
	return false
}

// MetaItem - единица произвольных метаданных записи. Хранится на сервере в открытом виде.
type MetaItem struct {
	Key   string // ключ, уникален в пределах записи
	Value string // значение
}

// Record - экземпляр записи с секретом.
//
// Заголовок (Type, Name, Meta) хранится открыто, зашифровано только тело записи.
type Record struct {
	UserID    string     // ссылка на пользователя, которому принадлежит запись
	ID        string     // ID записи
	Version   int64      // версия записи
	Revision  int64      // ревизия, в которой запись обновлялась в последний раз
	Deleted   bool       // признак удаления записи
	Type      RecordType // тип записи
	Name      string     // имя записи
	Meta      []MetaItem // метаданные записи, отсортированы по ключу
	Body      []byte     // зашифрованное тело записи
	BodyNonce []byte     // nonce зашифрованного тела записи
	UpdatedAt time.Time  // дата и время последнего обновления записи
}
