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
	Header, Body      crypto.Sealed
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

// Header - заголовок секрета. Хранит тип, наименование и мету. Возвращается в List.
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

// Validate проверяет заполненность имени и соответствие типа.
func (s Secret) Validate() error {
	if s.Header.Name == "" {
		return fmt.Errorf("empty secret name: %w", ErrInvalidData)
	}
	if s.Content == nil {
		return fmt.Errorf("nil content: %w", ErrInvalidData)
	}
	if s.Header.Type != s.Content.secretType() {
		return fmt.Errorf("header type mismatches content type: %w", ErrInvalidData)
	}
	return nil
}

// Marshal преобразует объект типа Secret в поток байт, которые можно отправить по сети.
func (s Secret) Marshal() (header, body []byte, err error) {
	if err := s.Validate(); err != nil {
		return nil, nil, err
	}

	ht, err := typeToProto(s.Header.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("type conversion in marshal: %w", err)
	}

	hb := payload.SecretHeader_builder{Type: ht, Name: s.Header.Name}
	for _, v := range s.Header.Meta {
		hb.Meta = append(hb.Meta, payload.Meta_builder{Key: v.Key, Value: v.Value}.Build())
	}
	header, err = proto.Marshal(hb.Build())
	if err != nil {
		return nil, nil, fmt.Errorf("marshal header: %w", err)
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
		return nil, nil, fmt.Errorf("marshal body: %w", err)
	}
	return header, body, nil
}

// UnmarshalHeader преобразует поток байт в Header. Нужен для List.
func UnmarshalHeader(b []byte) (Header, error) {
	var h payload.SecretHeader
	if err := proto.Unmarshal(b, &h); err != nil {
		return Header{}, fmt.Errorf("unmarshal header: %w", err)
	}

	ht, err := protoToType(h.GetType())
	if err != nil {
		return Header{}, fmt.Errorf("unmarshal header conversion error: %w", err)
	}

	header := Header{
		Type: ht,
		Name: h.GetName(),
	}
	for _, meta := range h.GetMeta() {
		header.Meta = append(header.Meta, MetaItem{Key: meta.GetKey(), Value: meta.GetValue()})
	}
	return header, nil
}

// Unmarshal преобразует потоки байт в цельный Secret. Нужен для Get.
func Unmarshal(header, body []byte) (Secret, error) {
	h, err := UnmarshalHeader(header) // proto.Unmarshal в SecretHeader → domain.Header
	if err != nil {
		return Secret{}, err
	}

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

	return Secret{Header: h, Content: c}, nil
}

func typeToProto(t RecType) (protoType payload.SecretHeader_SecretType, err error) {
	switch t {
	case TypeLogin:
		protoType = payload.SecretHeader_LOGIN
	case TypeText:
		protoType = payload.SecretHeader_TEXT
	case TypeBinary:
		protoType = payload.SecretHeader_BINARY
	case TypeCard:
		protoType = payload.SecretHeader_CARD
	default:
		return payload.SecretHeader_SECRET_TYPE_UNSPECIFIED, fmt.Errorf("unexpected type %s", t)
	}
	return
}

func protoToType(pt payload.SecretHeader_SecretType) (headerType RecType, err error) {
	switch pt {
	case payload.SecretHeader_LOGIN:
		headerType = TypeLogin
	case payload.SecretHeader_TEXT:
		headerType = TypeText
	case payload.SecretHeader_BINARY:
		headerType = TypeBinary
	case payload.SecretHeader_CARD:
		headerType = TypeCard
	default:
		return "", fmt.Errorf("unexpected type in proto: %s", pt)
	}
	return
}
