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

package msha1

import (
	"hash"
	"unsafe"
)

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lisal_crypto
// #include <isa-l_crypto/mh_sha1.h>
import "C"

func init() {
	// TODO: Plumb into crypto hash registry
	// crypto.RegisterHash(crypto.MH, New)
}

// The size of a checksum in bytes.
const Size = 20

// The blocksize in bytes.
const BlockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
	hash [Size]byte

	ctx C.struct_mh_sha1_ctx
}

func (d *digest) Reset() {
	C.mh_sha1_init(&d.ctx)
}

// New returns a new hash.Hash computing the multi hash SHA1 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()

	return d
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

func (d *digest) Write(p []byte) (int, error) {
	lp := len(p)
	if lp == 0 {
		return 0, nil
	}

	bufPtr := unsafe.Pointer(&p[0])
	bufLen := C.uint32_t(len(p))

	C.mh_sha1_update(&d.ctx, bufPtr, bufLen)

	return lp, nil
}

func (d digest) finalize() [Size]byte {
	hashPtr := unsafe.Pointer(&d.hash[0])
	C.mh_sha1_finalize(&d.ctx, hashPtr)

	return d.hash
}

func (d digest) Sum(in []byte) []byte {
	hash := d.finalize()

	return append(in, hash[:]...)
}

// Sum returns the multi-hash SHA-1 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)

	return d.finalize()
}
