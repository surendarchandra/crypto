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
	"bytes"
	gaes "crypto/aes"
	gcipher "crypto/cipher"
	"testing"

	"github.com/surendarchandra/crypto/aes"
	"github.com/surendarchandra/crypto/cipher"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CryptoCBCSuite struct {
	plainText, cipherText, origText []byte
	iv                              []byte
	key128, key256                  cipher.Block
}

var _ = Suite(&CryptoCBCSuite{})

const (
	blockSize = 4096
)

func (x *CryptoCBCSuite) SetUpSuite(c *C) {
	x.plainText = make([]byte, blockSize, blockSize)
	x.cipherText = make([]byte, blockSize, blockSize)
	x.origText = make([]byte, blockSize, blockSize)
	x.iv = make([]byte, aes.BlockSize, aes.BlockSize)

	var err error
	k := make([]byte, 128/8, 128/8)
	x.key128, err = aes.NewCipher(k)
	c.Assert(err, IsNil)

	k = make([]byte, 256/8, 256/8)
	x.key256, err = aes.NewCipher(k)
	c.Assert(err, IsNil)
}

func (x *CryptoCBCSuite) BenchmarkCBCEncrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-128 Encrypt")

	k := make([]byte, 128/8, 128/8)
	k128, err := aes.NewCipher(k)
	c.Assert(err, IsNil)

	e := cipher.NewCBCEncrypter(k128, x.iv)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func (x *CryptoCBCSuite) BenchmarkCBCDecrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-128 Decrypt")

	k := make([]byte, 16, 16)
	k128, err := aes.NewCipher(k)
	c.Assert(err, IsNil)

	e := cipher.NewCBCDecrypter(k128, x.iv)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.plainText, x.cipherText)
	}
}

func (x *CryptoCBCSuite) BenchmarkCBCEncrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-256 Encrypt")

	k := make([]byte, 256/8, 256/8)
	k256, err := aes.NewCipher(k)
	c.Assert(err, IsNil)

	e := cipher.NewCBCEncrypter(k256, x.iv)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func (x *CryptoCBCSuite) BenchmarkCBCDecrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-256 Decrypt")

	k := make([]byte, 256/8, 256/8)
	k256, err := aes.NewCipher(k)
	c.Assert(err, IsNil)

	e := cipher.NewCBCDecrypter(k256, x.iv)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.plainText, x.cipherText)
	}
}

func (x *CryptoCBCSuite) BenchmarkGoCBCEncrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-128 Encrypt - go builtin")

	k := make([]byte, 128/8, 128/8)
	k128, err := gaes.NewCipher(k)
	c.Assert(err, IsNil)

	e := gcipher.NewCBCEncrypter(k128, x.iv)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func (x *CryptoCBCSuite) BenchmarkGoCBCDecrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-128 Decrypt - go builtin")

	k := make([]byte, 128/8, 128/8)
	k128, err := gaes.NewCipher(k)
	c.Assert(err, IsNil)

	e := gcipher.NewCBCDecrypter(k128, x.iv)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func (x *CryptoCBCSuite) BenchmarkGoCBCEncrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-256 Encrypt - go builtin")

	k := make([]byte, 32, 32)
	k256, err := gaes.NewCipher(k)
	c.Assert(err, IsNil)

	e := gcipher.NewCBCEncrypter(k256, x.iv)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func (x *CryptoCBCSuite) BenchmarkGoCBCDecrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-CBC-256 Decrypt - go builtin")

	k := make([]byte, 256/8, 256/8)
	k256, err := gaes.NewCipher(k)
	c.Assert(err, IsNil)

	e := gcipher.NewCBCDecrypter(k256, x.iv)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.CryptBlocks(x.cipherText, x.plainText)
	}
}

func TestCBCEncrypterThisAES(t *testing.T) {
	t.Log("AES-CBC Encrypt, same test as go builtin")

	for _, test := range cbcAESTests {
		c, err := aes.NewCipher(test.key)
		if err != nil {
			t.Errorf("%s: NewCipher(%d bytes) = %s", test.name, len(test.key), err)
			continue
		}

		encrypter := cipher.NewCBCEncrypter(c, test.iv)

		data := make([]byte, len(test.in))
		copy(data, test.in)

		encrypter.CryptBlocks(data, data)
		if !bytes.Equal(test.out, data) {
			t.Errorf("%s: CBCEncrypter\nhave %x\nwant %x", test.name, data, test.out)
		}
	}
}

func TestCBCDecrypterThisAES(t *testing.T) {
	t.Log("AES-CBC Decrypt, same test as go builtin")

	for _, test := range cbcAESTests {
		c, err := aes.NewCipher(test.key)
		if err != nil {
			t.Errorf("%s: NewCipher(%d bytes) = %s", test.name, len(test.key), err)
			continue
		}

		decrypter := cipher.NewCBCDecrypter(c, test.iv)

		data := make([]byte, len(test.out))
		copy(data, test.out)

		decrypter.CryptBlocks(data, data)
		if !bytes.Equal(test.in, data) {
			t.Errorf("%s: CBCDecrypter\nhave %x\nwant %x", test.name, data, test.in)
		}
	}
}
