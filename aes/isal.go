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

//+build !386

package aes

import (
	"errors"
	"unsafe"

	"github.com/surendarchandra/crypto/cipher"
)

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lisal_crypto
// #include <isa-l_crypto/aes_cbc.h>
// #include <isa-l_crypto/aes_gcm.h>
// #include <isa-l_crypto/aes_keyexp.h>
// #include <isa-l_crypto/aes_xts.h>
import "C"

// For CBC-128 or GCM-128. Must be aligned to 16 byte boundary
// by allocating from heap
type isal128Cipher struct {
	expkeyEnc, expkeyDec [BlockSize * 11]byte

	iv [BlockSize]byte

	// internal GCM key info
	gcmKeyData     C.struct_gcm_key_data
	authTag        [16]byte
	additionalData []byte
	gctx           C.struct_gcm_context_data
}

var _ cipher.Block = &isal128Cipher{}

func (a *isal128Cipher) Encrypt(cipherText, plainText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		encPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyEnc[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		C.aes_cbc_enc_128(plainTextPtr, ivPtr, encPtr, cipherTextPtr, C.uint64_t(len(plainText)))

		return nil
	case cipher.ModeGCM:
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		tagPtr := (*C.uint8_t)(unsafe.Pointer(&a.authTag[0]))
		gkeyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(&a.gcmKeyData))
		gctx := &a.gctx

		adPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		adLen := C.uint64_t(len(a.additionalData))
		if adLen > 0 {
			adPtr = (*C.uint8_t)(unsafe.Pointer(&a.additionalData[0]))
		}

		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		plainTextLen := C.uint64_t(len(plainText))
		if plainTextLen > 0 {
			plainTextPtr = (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		}

		C.aes_gcm_enc_128(gkeyDataPtr, gctx, cipherTextPtr, plainTextPtr, plainTextLen, ivPtr, adPtr, adLen, tagPtr, C.uint64_t(len(a.authTag)))

		return nil
	}

	return errors.New("Invalid mode: ")
}

func (a *isal128Cipher) Decrypt(plainText, cipherText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		decPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyDec[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		// ISA-L_crypto allows in place operations though
		// operating on the same buffer did not work
		// TODO: Check if in-place operations are possible
		if cipherTextPtr == plainTextPtr {
			ct := make([]byte, len(cipherText))
			// Could be accelerated using H/W
			copy(ct, cipherText)
			cipherTextPtr = unsafe.Pointer(&ct[0])
		}

		C.aes_cbc_dec_128(cipherTextPtr, ivPtr, decPtr, plainTextPtr, C.uint64_t(len(cipherText)))

		return nil
	case cipher.ModeGCM:
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		tagPtr := (*C.uint8_t)(unsafe.Pointer(&a.authTag[0]))
		gkeyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(&a.gcmKeyData))
		gctx := &a.gctx

		adPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		adLen := C.uint64_t(len(a.additionalData))
		if adLen > 0 {
			adPtr = (*C.uint8_t)(unsafe.Pointer(&a.additionalData[0]))
		}

		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		plainTextLen := C.uint64_t(len(plainText))
		if plainTextLen > 0 {
			plainTextPtr = (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		}
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		cipherTextLen := C.uint64_t(len(cipherText))
		if cipherTextLen > 0 {
			cipherTextPtr = (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))
		}

		// memset authTag to 0
		for i, _ := range a.authTag {
			a.authTag[i] = 0
		}

		C.aes_gcm_dec_128(gkeyDataPtr, gctx, plainTextPtr, cipherTextPtr, cipherTextLen, ivPtr, adPtr, adLen, tagPtr, C.uint64_t(len(a.authTag)))

		return nil
	}

	return errors.New("Invalid mode")
}

func (a *isal128Cipher) SetIV(iv []byte) {
	copy(a.iv[:], iv)
}

func (a *isal128Cipher) BlockSize() int {
	return BlockSize
}

func (a *isal128Cipher) GCMAddAdditionalData(addData []byte) {
	a.additionalData = make([]byte, len(addData), len(addData))

	copy(a.additionalData, addData)
}

func (a *isal128Cipher) GCMGetAuthTag() []byte {
	return a.authTag[:]
}

// For CBC-192 or GCM-192.  Must be aligned to 16 byte boundary
// by allocating from heap
type isal192Cipher struct {
	expkeyEnc, expkeyDec [BlockSize * 13]byte

	iv [BlockSize]byte
}

var _ cipher.Block = &isal192Cipher{}

func (a *isal192Cipher) Encrypt(cipherText, plainText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		encPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyEnc[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		C.aes_cbc_enc_192(plainTextPtr, ivPtr, encPtr, cipherTextPtr, C.uint64_t(len(plainText)))

		return nil
	case cipher.ModeGCM:
		return errors.New("AES-GCM-192 not implemented")
	}

	return errors.New("Invalid mode")
}

func (a *isal192Cipher) Decrypt(plainText, cipherText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		decPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyDec[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		// ISA-L_crypto allows in place operations though
		// operating on the same buffer did not work
		// TODO: Check if in-place operations are possible
		if cipherTextPtr == plainTextPtr {
			ct := make([]byte, len(cipherText))
			copy(ct, cipherText)
			cipherTextPtr = unsafe.Pointer(&ct[0])
		}

		C.aes_cbc_dec_192(cipherTextPtr, ivPtr, decPtr, plainTextPtr, C.uint64_t(len(cipherText)))

		return nil
	case cipher.ModeGCM:
		return errors.New("AES-GCM-192 not implemented")
	}

	return errors.New("Invalid mode")
}

func (a *isal192Cipher) SetIV(iv []byte) {
	copy(a.iv[:], iv)
}

func (a *isal192Cipher) BlockSize() int {
	return BlockSize
}

func (a *isal192Cipher) GCMAddAdditionalData(addData []byte) {

}

func (a *isal192Cipher) GCMGetAuthTag() []byte {
	return nil
}

// For CBC-256, GCM-256 or XTS-128. Specific mode is unknown
// while expanded and so expand for both modes
// Must be aligned to 16 byte boundary
type isal256Cipher struct {
	expkeyEnc, expkeyDec [BlockSize * 15]byte

	// XTS-128 splits the 256 bit keys into two 128 bit keys
	xtsExpkey1Enc, xtsExpkey1Dec, xtsExpkey2Enc, unused [BlockSize * 11]byte

	iv [BlockSize]byte

	// internal GCM key info
	gcmKeyData     C.struct_gcm_key_data
	authTag        [16]byte
	additionalData []byte
	gctx           C.struct_gcm_context_data
}

var _ cipher.Block = &isal256Cipher{}

func (a *isal256Cipher) Encrypt(cipherText, plainText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		encPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyEnc[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		C.aes_cbc_enc_256(plainTextPtr, ivPtr, encPtr, cipherTextPtr, C.uint64_t(len(plainText)))

		return nil
	case cipher.ModeGCM:
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		tagPtr := (*C.uint8_t)(unsafe.Pointer(&a.authTag[0]))
		gkeyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(&a.gcmKeyData))
		gctx := &a.gctx

		adPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		adLen := C.uint64_t(len(a.additionalData))
		if adLen > 0 {
			adPtr = (*C.uint8_t)(unsafe.Pointer(&a.additionalData[0]))
		}

		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		plainTextLen := C.uint64_t(len(plainText))
		if plainTextLen > 0 {
			plainTextPtr = (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		}

		C.aes_gcm_enc_256(gkeyDataPtr, gctx, cipherTextPtr, plainTextPtr, plainTextLen, ivPtr, adPtr, adLen, tagPtr, C.uint64_t(len(a.authTag)))

		return nil
	case cipher.ModeXTS:
		enc2Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey2Enc[0]))
		enc1Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey1Enc[0]))
		tweakPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))

		C.XTS_AES_128_enc_expanded_key(enc2Ptr, enc1Ptr, tweakPtr, C.uint64_t(len(plainText)), plainTextPtr, cipherTextPtr)

		return nil
	}

	return errors.New("Invalid mode")
}

func (a *isal256Cipher) Decrypt(plainText, cipherText []byte, mode int) error {
	switch mode {
	case cipher.ModeCBC:
		decPtr := (*C.uint8_t)(unsafe.Pointer(&a.expkeyDec[0]))
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := unsafe.Pointer(&plainText[0])
		cipherTextPtr := unsafe.Pointer(&cipherText[0])

		// ISA-L_crypto allows in place operations though
		// operating on the same buffer did not work
		// TODO: Check if in-place operations are possible
		if cipherTextPtr == plainTextPtr {
			ct := make([]byte, len(cipherText))
			copy(ct, cipherText)
			cipherTextPtr = unsafe.Pointer(&ct[0])
		}

		C.aes_cbc_dec_256(cipherTextPtr, ivPtr, decPtr, plainTextPtr, C.uint64_t(len(cipherText)))

		return nil
	case cipher.ModeGCM:
		ivPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		tagPtr := (*C.uint8_t)(unsafe.Pointer(&a.authTag[0]))
		gkeyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(&a.gcmKeyData))
		gctx := &a.gctx

		adPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		adLen := C.uint64_t(len(a.additionalData))
		if adLen > 0 {
			adPtr = (*C.uint8_t)(unsafe.Pointer(&a.additionalData[0]))
		}

		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		plainTextLen := C.uint64_t(len(plainText))
		if plainTextLen > 0 {
			plainTextPtr = (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		}
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(nil))
		cipherTextLen := C.uint64_t(len(cipherText))
		if cipherTextLen > 0 {
			cipherTextPtr = (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))
		}

		// memset authTag to 0
		for i, _ := range a.authTag {
			a.authTag[i] = 0
		}

		C.aes_gcm_dec_256(gkeyDataPtr, gctx, plainTextPtr, cipherTextPtr, cipherTextLen, ivPtr, adPtr, adLen, tagPtr, C.uint64_t(len(a.authTag)))

		return nil
	case cipher.ModeXTS:
		enc2Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey2Enc[0]))
		dec1Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey1Dec[0]))
		tweakPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))

		C.XTS_AES_128_dec_expanded_key(enc2Ptr, dec1Ptr, tweakPtr, C.uint64_t(len(cipherText)), cipherTextPtr, plainTextPtr)

		return nil
	}

	return errors.New("Invalid mode")
}

func (a *isal256Cipher) SetIV(iv []byte) {
	copy(a.iv[:], iv)
}

func (a *isal256Cipher) BlockSize() int {
	return BlockSize
}

func (a *isal256Cipher) GCMAddAdditionalData(addData []byte) {
	a.additionalData = make([]byte, len(addData), len(addData))

	copy(a.additionalData, addData)
}

func (a *isal256Cipher) GCMGetAuthTag() []byte {
	return a.authTag[:]
}

// Struct for XTS-256.  Must be aligned to 16 byte boundary
type isal512Cipher struct {
	xtsExpkey1Enc, xtsExpkey2Enc, xtsExpkey1Dec, unused [BlockSize * 15]byte
	iv                                                  [BlockSize]byte // poor man's uint128
}

var _ cipher.Block = &isal512Cipher{}

func (a *isal512Cipher) Encrypt(cipherText, plainText []byte, mode int) error {
	switch mode {
	case cipher.ModeXTS:
		enc2Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey2Enc[0]))
		enc1Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey1Enc[0]))
		tweakPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))

		C.XTS_AES_256_enc_expanded_key(enc2Ptr, enc1Ptr, tweakPtr, C.uint64_t(len(plainText)), plainTextPtr, cipherTextPtr)

		return nil
	}

	return errors.New("Invalid mode")
}

func (a *isal512Cipher) Decrypt(plainText, cipherText []byte, mode int) error {
	switch mode {
	case cipher.ModeXTS:
		enc2Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey2Enc[0]))
		dec1Ptr := (*C.uint8_t)(unsafe.Pointer(&a.xtsExpkey1Dec[0]))
		tweakPtr := (*C.uint8_t)(unsafe.Pointer(&a.iv[0]))
		plainTextPtr := (*C.uint8_t)(unsafe.Pointer(&plainText[0]))
		cipherTextPtr := (*C.uint8_t)(unsafe.Pointer(&cipherText[0]))

		C.XTS_AES_256_dec_expanded_key(enc2Ptr, dec1Ptr, tweakPtr, C.uint64_t(len(cipherText)), cipherTextPtr, plainTextPtr)

		return nil
	}

	return errors.New("Invalid mode")
}

func (a *isal512Cipher) SetIV(iv []byte) {
	copy(a.iv[:], iv)

}

func (a *isal512Cipher) BlockSize() int {
	return BlockSize
}

func (a *isal512Cipher) GCMAddAdditionalData(addData []byte) {
	return
}

func (a *isal512Cipher) GCMGetAuthTag() []byte {
	return nil
}

// Wrapper functions around ISA_L-crypto key expansion functions.
// aes_cbc_enc() function is not exported from ISA-l library
// and so use a unused buffer
func isalKeyExpand128(key, enc, dec []byte) {
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	encPtr := (*C.uint8_t)(unsafe.Pointer(&enc[0]))
	decPtr := (*C.uint8_t)(unsafe.Pointer(&dec[0]))

	C.aes_keyexp_128(keyPtr, encPtr, decPtr)
}

func isalKeyExpand192(key, enc, dec []byte) {
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	encPtr := (*C.uint8_t)(unsafe.Pointer(&enc[0]))
	decPtr := (*C.uint8_t)(unsafe.Pointer(&dec[0]))

	C.aes_keyexp_192(keyPtr, encPtr, decPtr)

}

func isalKeyExpand256(key, enc, dec []byte) {
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	encPtr := (*C.uint8_t)(unsafe.Pointer(&enc[0]))
	decPtr := (*C.uint8_t)(unsafe.Pointer(&dec[0]))

	C.aes_keyexp_256(keyPtr, encPtr, decPtr)
}

func isalGCMPrecomp128(key []byte, keyData *C.struct_gcm_key_data) {
	keyPtr := unsafe.Pointer(&key[0])
	keyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(keyData))

	C.aes_gcm_pre_128(keyPtr, keyDataPtr)
}

func isalGCMPrecomp256(key []byte, keyData *C.struct_gcm_key_data) {
	keyPtr := unsafe.Pointer(&key[0])
	keyDataPtr := (*C.struct_gcm_key_data)(unsafe.Pointer(keyData))

	C.aes_gcm_pre_256(keyPtr, keyDataPtr)
}
