package goscs

import (
	"bytes"
	"testing"
)

type expectations struct {
	input, expected []byte
}

func TestAddPadding(t *testing.T) {
	data := []expectations{
		{[]byte("abcdefghijklmno"), []byte("abcdefghijklmno\x01")},
		{[]byte("abcdefghijklmn"), []byte("abcdefghijklmn\x02\x02")},
		{[]byte("abcdefghijklmnopq"),
			[]byte("abcdefghijklmnopq\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")},
		{[]byte("a"), []byte("a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f")},
		{[]byte(""), bytes.Repeat([]byte{byte(0x10)}, 0x10)},
	}

	for _, exp := range data {
		padded := addPadding(exp.input)
		if !bytes.Equal(padded, exp.expected) {
			t.Errorf("addPadding(%q) = %q, expected %q", exp.input, padded, exp.expected)
		}
	}
}
