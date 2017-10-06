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

package cipher

import (
	"errors"
)

// Go crypto uses a different cipher.Block for encryption and decryption.
// Unnecessary for XTS mode where IV must be specified for each block.
// Therefore, we support Encryption or Decryption on the same Block but
// remember the operation.
type cbc struct {
	block     Block
	mode      int
	operation int
}

// NewCBCEncrypter creates a AES-CBC encryption system
func NewCBCEncrypter(b Block, iv []byte) BlockMode {
	c := &cbc{block: b, mode: ModeCBC, operation: OperationEncrypt}

	if len(iv) != c.block.BlockSize() {
		panic("cipher.NewCBCEncrypter: IV length must equal block size")
	}
	c.block.SetIV(iv)

	return c
}

// NewCBCDecrypter creates a AES-CBC decryption system
func NewCBCDecrypter(b Block, iv []byte) BlockMode {
	c := &cbc{block: b, mode: ModeCBC, operation: OperationDecrypt}

	if len(iv) != c.block.BlockSize() {
		panic("cipher.NewCBCEncrypter: IV length must equal block size")
	}
	c.block.SetIV(iv)

	return c
}

func (c *cbc) BlockSize() int {
	return c.block.BlockSize()
}

func (c *cbc) CryptBlocks(dst, src []byte) error {
	switch c.operation {
	case OperationEncrypt:
		return c.Encrypt(dst, src)
	case OperationDecrypt:
		return c.Decrypt(dst, src)
	}

	return errors.New("Unknown operation")
}

func (c *cbc) SetIV(iv []byte) {
	if len(iv) != c.block.BlockSize() {
		panic("cipher: incorrect length IV")
	}
	c.block.SetIV(iv)
}

func (c *cbc) Encrypt(cipherText, plainText []byte) error {
	return c.block.Encrypt(cipherText, plainText, c.mode)
}

func (c *cbc) Decrypt(plainText, cipherText []byte) error {
	return c.block.Decrypt(plainText, cipherText, c.mode)
}
