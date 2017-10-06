// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"testing"

	"github.com/surendarchandra/crypto/aes"
	"github.com/surendarchandra/crypto/cipher"
)

func benchmarkAESGCMSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkAESGCMOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	aes, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(aes)
	var out []byte
	out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aesgcm.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func BenchmarkAESGCMSeal1K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 1024))
}

func BenchmarkAESGCMOpen1K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 1024))
}

func BenchmarkAESGCMSeal8K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMOpen8K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 8*1024))
}

func BenchmarkAESCBCEncrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	cbc := cipher.NewCBCEncrypter(aes, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkAESCBCDecrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, _ := aes.NewCipher(key[:])
	cbc := cipher.NewCBCDecrypter(aes, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}
