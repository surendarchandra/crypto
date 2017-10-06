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
	"github.com/surendarchandra/crypto/aes"
	"github.com/surendarchandra/crypto/cipher"

	. "gopkg.in/check.v1"
)

type CryptoXTSSuite struct {
	plainText, cipherText, origText []byte
	iv                              []byte
	key128, key256                  cipher.Block
}

var _ = Suite(&CryptoXTSSuite{})

func (x *CryptoXTSSuite) SetUpSuite(c *C) {
	x.plainText = make([]byte, 4096, 4096)
	x.cipherText = make([]byte, 4096, 4096)
	x.origText = make([]byte, 4096, 4096)
	x.iv = make([]byte, 16, 16)

	var err error
	k := make([]byte, 256/8, 256/8)
	x.key128, err = aes.NewCipher(k)
	c.Assert(err, IsNil)

	k = make([]byte, 512/8, 512/8)
	x.key256, err = aes.NewCipher(k)
	c.Assert(err, IsNil)
}

func (x *CryptoXTSSuite) TestXTS(c *C) {
	if !aes.IsSupported() {
		return
	}

	// Check against standard data for AES-XTS
	for i, vector := range append(aesXts128TestVectors[:], aesXts256TestVectors[:]...) {
		c.Logf("Testing vector #%d (key length: %d bits)\n", i, len(vector.key1)*8)

		block, err := aes.NewCipher(append(vector.key1[:], vector.key2[:]...))
		c.Assert(err, IsNil)

		e := cipher.NewXTSEncryptor(block)
		e.SetIV(vector.tweak)

		ctx := make([]byte, len(vector.ctx), len(vector.ctx))
		err = e.Encrypt(ctx, vector.ptx)
		c.Assert(err, IsNil)
		c.Assert(ctx, DeepEquals, vector.ctx)

		ptx := make([]byte, len(vector.ptx), len(vector.ptx))

		err = e.Decrypt(ptx, vector.ctx)
		c.Assert(err, IsNil)
		c.Assert(ptx, DeepEquals, vector.ptx)
	}
}

func (x *CryptoXTSSuite) BenchmarkXTSEncrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-XTS-128 Encrypt")

	e := cipher.NewXTSEncryptor(x.key128)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.SetIV(x.iv)
		e.Encrypt(x.cipherText, x.plainText)
	}
}

func (x *CryptoXTSSuite) BenchmarkXTSDecrypt128(c *C) {
	c.StopTimer()
	c.Log("AES-XTS-128 Decrypt")

	e := cipher.NewXTSEncryptor(x.key128)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.SetIV(x.iv)
		e.Decrypt(x.plainText, x.cipherText)
	}
}

func (x *CryptoXTSSuite) BenchmarkXTSEncrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-XTS-256 Encrypt")

	e := cipher.NewXTSEncryptor(x.key256)
	c.SetBytes(int64(len(x.plainText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.SetIV(x.iv)
		e.Encrypt(x.cipherText, x.plainText)
	}
}

func (x *CryptoXTSSuite) BenchmarkXTSDecrypt256(c *C) {
	c.StopTimer()
	c.Log("AES-XTS-256 Decrypt")

	e := cipher.NewXTSEncryptor(x.key256)
	c.SetBytes(int64(len(x.cipherText)))

	c.StartTimer()

	for i := 0; i < c.N; i++ {
		e.SetIV(x.iv)
		e.Decrypt(x.plainText, x.cipherText)
	}
}
