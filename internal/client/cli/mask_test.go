package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMask(t *testing.T) {
	assert.NotContains(t, maskPassword(), "hunter2")
	assert.NotContains(t, maskCVV(), "123")

	num := "4111111111111111"
	masked := maskCardNumber(num)
	assert.NotEqual(t, num, masked)
	assert.NotContains(t, masked, num[4:12], "середина номера не должна попадать в вывод")
}

func TestMaskCardNumber_Short(t *testing.T) {
	for _, num := range []string{"", "1", "123", "1234", "1234567", "123456789012345"} {
		got := maskCardNumber(num)
		assert.Len(t, got, len(num), "number=%q", num)
		assert.NotRegexp(t, `\d`, got, "в коротком номере не должно остаться цифр: number=%q", num)
	}
}
