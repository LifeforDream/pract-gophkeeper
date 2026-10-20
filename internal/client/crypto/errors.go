package crypto

import "errors"

var (
	// ErrInvalidParams выбрасывается Validate() в случае, когда параметры некорректны.
	ErrInvalidParams = errors.New("crypto: invalid KDF params")
	// ErrInvalidKey выбрасывается при несовпадении размера ключа.
	ErrInvalidKey = errors.New("crypto: invalid key length")
	// ErrInvalidSalt выбрасывается, если "соль" от сервера слишком короткая.
	ErrInvalidSalt = errors.New("crypto: invalid salt length")
	// ErrDecrypt используется для ошибок шифрования/дешифрования.
	ErrDecrypt = errors.New("crypto: decryption failed")
)
