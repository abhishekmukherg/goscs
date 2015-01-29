package scs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"time"
	"strconv"
	"log"
	"strings"
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

func (s *Scs) cryptData(data, iv []byte) (out []byte) {
	out = make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(s.aes, iv)
	mode.CryptBlocks(out, data)
	return out
}


func (s *Scs) authToken(eData, eAtime, eTid, eIv string) []byte {
	unmac := box(eData, eAtime, eTid, eIv)
	macDaddy := hmac.New(sha1.New, s.key)
	macDaddy.Write([]byte(unmac))
	return macDaddy.Sum(nil)
}

func box(parts ...string) string {
	return strings.Join(parts, "|")
}
