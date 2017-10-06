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

// Mimic's Go built in crypto/gcm

package cipher

import (
	"crypto/subtle"
	"errors"
)

// AEAD is a cipher mode providing authenticated encryption with associated
// data. For a description of the methodology, see
//	https://en.wikipedia.org/wiki/Authenticated_encryption
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// The plaintext and dst may alias exactly or not at all. To reuse
	// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// The ciphertext and dst may alias exactly or not at all. To reuse
	// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// gcm represents a Galois Counter Mode with a specific key. See
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	block Block

	nonceSize int
}

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
//
// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying Block was created by aes.NewCipher
// on systems with hardware support for AES. See the crypto/aes package documentation for details.
func NewGCM(block Block) (AEAD, error) {
	return &gcm{block: block, nonceSize: gcmStandardNonceSize}, nil
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length.
// NOT IMPLEMENTED
func NewGCMWithNonceSize(block Block, size int) (AEAD, error) {
	if size != gcmStandardNonceSize {
		return nil, errors.New("Non standard nonce size not implemented")
	}

	return NewGCM(block)
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func (g *gcm) NonceSize() int {
	return g.nonceSize
}

func (*gcm) Overhead() int {
	return gcmTagSize
}

func (g *gcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}

	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(g.block.BlockSize()) {
		panic("cipher: message too large for GCM")
	}

	ret, _ := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	g.block.SetIV(nonce)
	g.block.GCMAddAdditionalData(additionalData)
	g.block.Encrypt(ret, plaintext, ModeGCM)
	// copy authentication tag
	copy(ret[len(plaintext):], g.block.GCMGetAuthTag())

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}

	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(g.block.BlockSize())+gcmTagSize {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	ret, out := sliceForAppend(dst, len(ciphertext))

	g.block.SetIV(nonce)
	g.block.GCMAddAdditionalData(additionalData)
	g.block.Decrypt(ret, ciphertext, ModeGCM)

	if subtle.ConstantTimeCompare(g.block.GCMGetAuthTag(), tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	return ret, nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
