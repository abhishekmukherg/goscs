package goscs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/hmac"
	"encoding/base64"
	"time"
	"bytes"
	"strconv"
	"log"
	"errors"
)

var BadInputError = errors.New("Bad Input")

type Scs struct {
	key []byte
	aes cipher.Block
	sessionMaxAge time.Duration
}

func New(key []byte) *Scs {
	a, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create cypher: %q\n", err)
		return nil
	}
	return &Scs{key, a, time.Minute}
}

func (s *Scs) Generate(data []byte) (string, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return "", err
	}

	tid := "1"

	atimeInt := time.Now().Unix()
	atime := strconv.FormatInt(atimeInt, 16)

	data = addPadding(data)
	out := s.cryptData(data, iv)

	eData := base64.StdEncoding.EncodeToString(out)
	eAtime := base64.StdEncoding.EncodeToString([]byte(atime))
	eTid := base64.StdEncoding.EncodeToString([]byte(tid))
	eIv := base64.StdEncoding.EncodeToString(iv)
	authtag := s.authToken(eData, eAtime, eTid, eIv)
	eAuthtag := base64.StdEncoding.EncodeToString(authtag)

	return box(eData, eAtime, eTid, eIv, eAuthtag), nil
}

func (s *Scs) Parse(input string) ([]byte, error) {
	splits := unbox(input)
	if len(splits) != 5 {
		return nil, BadInputError
	}
	eData := splits[0]
	eAtime := splits[1]
	eTid := splits[2]
	eIv := splits[3]
	eAuthtag := splits[4]

	tid, err := base64.StdEncoding.DecodeString(eTid)
	if err != nil {
		return nil, err
	}

	// todo: validate tid
	if !bytes.Equal(tid, []byte("1")) {
		return nil, BadInputError
	}

	givenAuthtag, err := base64.StdEncoding.DecodeString(eAuthtag)
	if err != nil {
		return nil, err
	}
	expectedAuthtag := s.authToken(eData, eAtime, eTid, eIv)

	if !hmac.Equal(givenAuthtag, expectedAuthtag) {
		return nil, BadInputError
	}

	atime, err := base64.StdEncoding.DecodeString(eAtime)
	if err != nil {
		return nil, err
	}
	realAtimeUnix, err := strconv.ParseInt(string(atime), 16, 64)
	if err != nil {
		return nil, err
	}
	realAtime := time.Unix(realAtimeUnix, 0)
	now := time.Now()
	duration := now.Sub(realAtime)
	if duration > s.sessionMaxAge {
		return nil, BadInputError
	}

	iv, err := base64.StdEncoding.DecodeString(eIv)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(eData)
	if err != nil {
		return nil, err
	}

	out := s.uncryptData(data, iv)
	return out, nil
}
