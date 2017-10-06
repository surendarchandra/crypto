// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	aes "crypto/aes"
	cipher "crypto/cipher"
	"testing"
)

func benchmarkGoAESGCMSeal(b *testing.B, buf []byte) {
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

func benchmarkGoAESGCMOpen(b *testing.B, buf []byte) {
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

func BenchmarkGoAESGCMSeal1K(b *testing.B) {
	benchmarkGoAESGCMSeal(b, make([]byte, 1024))
}

func BenchmarkGoAESGCMOpen1K(b *testing.B) {
	benchmarkGoAESGCMOpen(b, make([]byte, 1024))
}

func BenchmarkGoAESGCMSeal8K(b *testing.B) {
	benchmarkGoAESGCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkGoAESGCMOpen8K(b *testing.B) {
	benchmarkGoAESGCMOpen(b, make([]byte, 8*1024))
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5

func BenchmarkGoAESCBCEncrypt1K(b *testing.B) {
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

func BenchmarkGoAESCBCDecrypt1K(b *testing.B) {
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
