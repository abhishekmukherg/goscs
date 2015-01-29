package scs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"time"
	"strconv"
	"log"
)

type Scs struct {
	key []byte
	aes cipher.Block
}

func New(key []byte) *Scs {
	a, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create cypher: %q\n", err)
		return nil
	}
	return &Scs{key, a}
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
	authtoken := s.authToken(eData, eAtime, eTid, eIv)
	eAuthtoken := base64.StdEncoding.EncodeToString(authtoken)

	return box(eData, eAtime, eTid, eIv, eAuthtoken), nil
}
