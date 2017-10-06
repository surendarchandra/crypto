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

type xtsEncryptor struct {
	block Block
	mode  int
}

// NewXTSEncryptor creates a AES-XTS system
func NewXTSEncryptor(k Block) BlockMode {
	return &xtsEncryptor{block: k, mode: ModeXTS}
}

func (x *xtsEncryptor) Encrypt(cipherText, plainText []byte) error {
	err := x.validate(cipherText, plainText)
	if err != nil {
		return err
	}

	return x.block.Encrypt(cipherText, plainText, x.mode)
}

func (x *xtsEncryptor) Decrypt(plainText, cipherText []byte) error {
	err := x.validate(plainText, cipherText)
	if err != nil {
		return err
	}

	return x.block.Decrypt(plainText, cipherText, x.mode)
}

func (x *xtsEncryptor) SetIV(iv []byte) {
	if len(iv) != x.block.BlockSize() {
		panic("IV length must equal cipher block size")
	}
	x.block.SetIV(iv)
}

func (x *xtsEncryptor) BlockSize() int {
	return 1
}

func (x *xtsEncryptor) CryptBlocks(dst, src []byte) error {
	return errors.New("Not implemented")
}

func (x *xtsEncryptor) validate(dst, src []byte) error {
	if len(dst) < x.block.BlockSize() {
		return errors.New("Source buffer too small")
	}
	if len(dst) < len(src) {
		return errors.New("Destination buffer too small")
	}

	return nil
}
