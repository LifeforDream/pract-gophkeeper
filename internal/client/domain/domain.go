// Package domain хранит определение моделей, используемых клиентом.
package domain

import (
	"fmt"

	payload "github.com/LifeforDream/pract-gophkeeper/api/gophkeeper/payload/v1"
	"github.com/LifeforDream/pract-gophkeeper/internal/client/crypto"
	"google.golang.org/protobuf/proto"
)

// Record - запись с секретом.
type Record struct { // не proto
	ID                string
	Header                          // открытый заголовок: тип, имя, мета
	Body              crypto.Sealed // зашифрованное тело
	Version, Revision int64
	Deleted           bool
}

// RecType - тип записи.
type RecType string

const (
	// TypeLogin представляет пару логин-пароль.
	TypeLogin RecType = "login"
	// TypeBinary представляет бинарные данные (файл).
	TypeBinary RecType = "binary"
	// TypeText представляет произвольный текст.
	TypeText RecType = "text"
	// TypeCard представляет данные карты.
	TypeCard RecType = "card"
)

// MetaItem - единица метадаты записи.
type MetaItem struct{ Key, Value string }

// Header - заголовок секрета. Хранит тип, наименование и мету. Передаётся серверу открыто и возвращается в List.
type Header struct {
	Type RecType
	Name string
	Meta []MetaItem
}

// Content - содержимое секрета. Возвращается только в Get.
type Content interface{ secretType() RecType }

// Login - тип секрета "логин".
type Login struct{ Username, Password string }

func (Login) secretType() RecType { return TypeLogin }

// Text - тип секрета в виде вольного текста.
type Text string

func (Text) secretType() RecType { return TypeText }

// Binary - секрет в виде файла.
type Binary struct {
	Filename string
	Data     []byte
}

func (Binary) secretType() RecType { return TypeBinary }

// Card - данные карты как секрет.
type Card struct{ Number, Holder, Expiry, CVV string }

func (Card) secretType() RecType { return TypeCard }

// Secret - запись с секретом.
type Secret struct {
	Header
	Content Content
}

// Validate проверяет заполненность имени, соответствие типа и уникальность ключей меты (их требует сервер).
func (s Secret) Validate() error {
	if s.Header.Name == "" {
		return fmt.Errorf("empty secret name: %w", ErrInvalidData)
	}
	seen := make(map[string]struct{}, len(s.Header.Meta))
	for _, item := range s.Header.Meta {
		if item.Key == "" {
			return fmt.Errorf("empty meta key: %w", ErrInvalidData)
		}
		if _, dup := seen[item.Key]; dup {
			return fmt.Errorf("duplicate meta key %q: %w", item.Key, ErrInvalidData)
		}
		seen[item.Key] = struct{}{}
	}
	if s.Content == nil {
		return fmt.Errorf("nil content: %w", ErrInvalidData)
	}
	if s.Header.Type != s.Content.secretType() {
		return fmt.Errorf("header type mismatches content type: %w", ErrInvalidData)
	}
	return nil
}

// Marshal преобразует содержимое секрета в поток байт тела, который можно шифровать и отправлять по сети.
// Заголовок (тип, имя, мета) в тело не входит: он передаётся открыто.
func (s Secret) Marshal() (body []byte, err error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	cb := payload.SecretBody_builder{}
	switch c := s.Content.(type) {
	case Login:
		cb.Login = payload.Login_builder{Username: c.Username, Password: c.Password}.Build()
	case Text:
		cb.Text = proto.String(string(c))
	case Binary:
		cb.Binary = payload.Binary_builder{Filename: c.Filename, Content: c.Data}.Build()
	case Card:
		cb.Card = payload.Card_builder{
			Number: c.Number,
			Holder: c.Holder,
			Expiry: c.Expiry,
			Cvv:    c.CVV,
		}.Build()
	}
	body, err = proto.Marshal(cb.Build())
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	return body, nil
}

// Unmarshal собирает цельный Secret из открытого заголовка и расшифрованного тела. Нужен для Get.
//
// Тип в заголовке приходит от сервера и не защищён шифрованием, поэтому он сверяется с типом содержимого.
func Unmarshal(h Header, body []byte) (Secret, error) {
	var b payload.SecretBody
	if err := proto.Unmarshal(body, &b); err != nil {
		return Secret{}, fmt.Errorf("unmarshal secret: %w", err)
	}

	var c Content
	switch b.WhichContent() {
	case payload.SecretBody_Login_case:
		l := b.GetLogin()
		c = Login{Username: l.GetUsername(), Password: l.GetPassword()}
	case payload.SecretBody_Text_case:
		c = Text(b.GetText())
	case payload.SecretBody_Binary_case:
		c = Binary{Filename: b.GetBinary().GetFilename(), Data: b.GetBinary().GetContent()}
	case payload.SecretBody_Card_case:
		card := b.GetCard()
		c = Card{Number: card.GetNumber(), Holder: card.GetHolder(), Expiry: card.GetExpiry(), CVV: card.GetCvv()}
	default:
		return Secret{}, fmt.Errorf("body has no content")
	}
	if h.Type != c.secretType() {
		return Secret{}, fmt.Errorf("header type %q mismatches content type %q: %w", h.Type, c.secretType(), ErrInvalidData)
	}

	return Secret{Header: h, Content: c}, nil
}
