// MIT License
//
// Copyright (c) 2017 Surendar Chandra
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package cipher_test

import (
	gaes "crypto/aes"
	gcipher "crypto/cipher"

	"github.com/surendarchandra/crypto/aes"
	"github.com/surendarchandra/crypto/cipher"

	. "gopkg.in/check.v1"
)

type CryptoGCMSuite struct {
	plainText, cipherText, origText []byte
	nonce                           []byte
	key128, key256                  cipher.Block
	gkey128, gkey256                gcipher.Block
}

var _ = Suite(&CryptoGCMSuite{})

func (x *CryptoGCMSuite) SetUpSuite(c *C) {
	x.plainText = make([]byte, 4096, 4096)
	x.cipherText = make([]byte, 4096, 4096)
	x.origText = make([]byte, 4096, 4096)
	x.nonce = make([]byte, 12, 12)

	var err error
	k := make([]byte, 128/8, 128/8)
	x.key128, err = aes.NewCipher(k)
	c.Assert(err, IsNil)
	x.gkey128, err = gaes.NewCipher(k)
	c.Assert(err, IsNil)

	k = make([]byte, 256/8, 256/8)
	x.key256, err = aes.NewCipher(k)
	c.Assert(err, IsNil)
	x.gkey256, err = gaes.NewCipher(k)
	c.Assert(err, IsNil)
}

func (x *CryptoGCMSuite) BenchmarkGCMEncrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Encrypt")

	e, err := cipher.NewGCM(x.key128)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Seal(nil, x.nonce, x.plainText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGCMDecrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Decrypt")

	e, err := cipher.NewGCM(x.key128)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Open(nil, x.nonce, x.cipherText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGoGCMEncrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Encrypt")

	e, err := gcipher.NewGCM(x.gkey128)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Seal(nil, x.nonce, x.plainText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGoGCMDecrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Decrypt")

	e, err := gcipher.NewGCM(x.gkey128)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Open(nil, x.nonce, x.cipherText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGCMEncrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-256 Encrypt")

	e, err := cipher.NewGCM(x.key256)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Seal(nil, x.nonce, x.plainText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGCMDecrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-256 Decrypt")

	e, err := cipher.NewGCM(x.key256)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Open(nil, x.nonce, x.cipherText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGoGCMEncrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Encrypt")

	e, err := gcipher.NewGCM(x.gkey256)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Seal(nil, x.nonce, x.plainText, nil)
	}
}

func (x *CryptoGCMSuite) BenchmarkGoGCMDecrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-GCM-128 Decrypt")

	e, err := gcipher.NewGCM(x.gkey256)
	c.Assert(err, IsNil)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.Open(nil, x.nonce, x.cipherText, nil)
	}
}
