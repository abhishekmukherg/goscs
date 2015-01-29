package scs

import (
	"crypto/aes"
	"math"
	"log"
)

func addPadding(slice []byte) []byte {
	curLen := len(slice)
	remainder := curLen % aes.BlockSize
	if remainder == 0 {
		return slice
	}

	newLen := curLen + (aes.BlockSize - remainder)
	if newLen > cap(slice) {
		newSlice := make([]byte, newLen + 1)
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0:newLen]
	fillValue := newLen - curLen
	if fillValue >= math.MaxUint8 {
		log.Fatalf("Received a fillValue: %d", fillValue)
	}
	fillValueByte := byte(fillValue)
	fillSlice := slice[curLen:newLen]
	for i := range fillSlice {
		fillSlice[i] = fillValueByte
	}
	return slice
}
