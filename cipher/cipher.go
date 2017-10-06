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

// Mimic Go builtin interfaces

// A Block represents an implementation of block cipher
// using a given key. It provides the capability to encrypt
// or decrypt individual blocks. The mode implementations
// extend that capability to streams of blocks.
type Block interface {
	BlockSize() int
	SetIV(iv []byte)

	GCMAddAdditionalData(addData []byte)
	GCMGetAuthTag() []byte

	Encrypt(dst, src []byte, mode int) error
	Decrypt(dst, src []byte, mode int) error
}

const (
	// ModeXTS is the AES-XTS mode
	ModeXTS = iota + 1

	// ModeGCM is the AES-GCM mode
	ModeGCM

	// ModeCBC is the AES-CBC mode
	ModeCBC
)

const (
	// OperationEncrypt to let CryptBlock perform Encryption
	OperationEncrypt = iota + 1

	// OperationDecrypt to let CryptBlock perform Encryption
	OperationDecrypt
)

// A BlockMode represents a block cipher running in a block-based mode (CBC,
// XTS etc).
type BlockMode interface {
	// BlockSize returns the mode's block size.
	BlockSize() int
	SetIV(iv []byte)

	Encrypt(dst, src []byte) error
	Decrypt(dst, src []byte) error

	CryptBlocks(dst, src []byte) error
}
