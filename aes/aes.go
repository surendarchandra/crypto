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

package aes

import (
	"errors"

	"github.com/klauspost/cpuid"
	"github.com/surendarchandra/crypto/cipher"
)

var aesniSupported bool

// BlockSize is the AES block size in bytes.
const BlockSize = 16

func init() {
	// CBC and GCM require AES-NI and SSE4.1
	aesniSupported = cpuid.CPU.AesNi() && cpuid.CPU.SSE4()
}

// IsSupported checks whether hardware acceleration is available
// via AES-NI and SSE 4.1 instructions. This package requires
// hardware support.
func IsSupported() bool {
	return aesniSupported
}

// NewCipher creates and returns a new cipher.Block from
// the provided symmetric encryption key. The keys must be
// 16 bytes for AES-CBC-128 and AES-GCM-128, 24 bytes for
// AES-CBC-192 and AES-GCM-192, 32 bytes for AES-CBC-256, AES-GCM-256
// and AES-XTS-128 and 64 bytes for AES-XTS-256
func NewCipher(key []byte) (cipher.Block, error) {
	if !IsSupported() {
		return nil, errors.New("H/W not supported")
	}

	switch len(key) {
	case 16:
		// 128 bit keys can be used for CBC-128 and GCM-128

		// Ensure 16byte alignment by allocating from heap
		block := new(isal128Cipher)

		isalKeyExpand128(key, block.expkeyEnc[:], block.expkeyDec[:])

		// For GCM 128
		isalGCMPrecomp128(key, &block.gcmKeyData)

		return block, nil

	case 24:
		// 192 bit keys can be used for CBC-192 and GCM-192

		// Ensure 16byte alignment by allocating from heap
		block := new(isal192Cipher)
		isalKeyExpand192(key, block.expkeyEnc[:], block.expkeyDec[:])

		return block, nil

	case 32:
		// 256 bit keys can be used by XTS-128 or (CBC-256 or GCM-256)

		// Must be aligned to 16 byte boundary
		// Ensure 16byte alignment by allocating from heap
		block := new(isal256Cipher)

		// For CBC-256 or GCM-256
		isalKeyExpand256(key, block.expkeyEnc[:], block.expkeyDec[:])

		// For XTS-128
		isalKeyExpand128(key[:15], block.xtsExpkey1Enc[:], block.xtsExpkey1Dec[:])
		isalKeyExpand128(key[16:], block.xtsExpkey2Enc[:], block.unused[:])

		// For GCM-256
		isalGCMPrecomp256(key, &block.gcmKeyData)

		return block, nil
	case 64:
		// 512 bit keys are used by XTS-256

		//  Must be aligned to 16 byte boundary
		// Ensure 16byte alignment by allocating from heap
		block := new(isal512Cipher)

		isalKeyExpand256(key[:31], block.xtsExpkey1Enc[:], block.xtsExpkey1Dec[:])
		isalKeyExpand256(key[32:], block.xtsExpkey2Enc[:], block.unused[:])

		return block, nil
	}

	return nil, errors.New("Unsupported key size")
}
