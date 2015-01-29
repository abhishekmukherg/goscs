package scs

import (
	"testing"
)

type generateExp struct {
	input []byte
	expected string
}

func TestGenerate(t *testing.T) {
	data := []generateExp {
		{[]byte("abcdefghijklmno"), "abcdefghijklmno\x01"},
		{[]byte("abcdefghijklmn"), "abcdefghijklmn\x02\x02"},
		{[]byte("abcdefghijklmnopq"),"abcdefghijklmnopq\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"},
		{[]byte("a"), "a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"},
		{[]byte(""), ""},
	}

	scs := New([]byte("deadbedwasfed123"))
	for _, exp := range data {
		padded, _ := scs.Generate(exp.input)
		if padded != exp.expected {
			t.Errorf("addPadding(%q) = %q, expected %q", exp.input, padded, exp.expected)
		}
	}
}
