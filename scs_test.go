package scs

import (
	"bytes"
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
		cookie, err := scs.Generate(exp.input)
		if err != nil {
			t.Errorf("Got a non-nil error encoding %q", err)
		}

		result, err := scs.Parse(cookie)
		if err != nil {
			t.Errorf("Got a non-nil error decoding %q", err)
		}

		if !bytes.Equal(exp.input, result) {
			t.Errorf("Parse(Generate(%q)) = %q", exp.input, result)
		}
	}
}
