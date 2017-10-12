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

package msha1_test

import (
	"hash"
	"testing"

	"github.com/surendarchandra/crypto/msha1"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type HashMHSuite struct {
	bench hash.Hash

	buf []byte
}

var _ = Suite(&HashMHSuite{})

func (h *HashMHSuite) SetUpSuite(c *C) {
	h.bench = msha1.New()

	h.buf = make([]byte, 32768)
}

func (h *HashMHSuite) TestMH(c *C) {
	for i := 0; i < len(h.buf); i++ {
		hash := msha1.Sum(h.buf[:i])

		h.bench.Reset()
		h.bench.Write(h.buf[:i])
		h.bench.Sum(h.buf[:0])

		c.Assert(hash[:], DeepEquals, h.buf[:h.bench.Size()])
	}
}

// Test the performance for hashing size buffer
func (h *HashMHSuite) benchmarkSize(c *C, size int64) {
	c.SetBytes(size)

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		h.bench.Reset()
		h.bench.Write(h.buf[:size])
		h.bench.Sum(h.buf[:0])
	}
}

func (h *HashMHSuite) BenchmarkMH16K(c *C) {
	c.Logf("Block size: 16KiB")
	h.benchmarkSize(c, 16384*2)
}

func (h *HashMHSuite) BenchmarkMH8K(c *C) {
	c.Logf("Block size: 8KiB")
	h.benchmarkSize(c, 8192)
}

func (h *HashMHSuite) BenchmarkMH4K(c *C) {
	c.Logf("Block size: 4KiB")
	h.benchmarkSize(c, 4096)
}

func (h *HashMHSuite) BenchmarkMH1K(c *C) {
	c.Logf("Block size: 1KiB")
	h.benchmarkSize(c, 1024)
}

func (h *HashMHSuite) BenchmarkMH320(c *C) {
	c.Logf("Block size: 320B")
	h.benchmarkSize(c, 320)
}

func (h *HashMHSuite) BenchmarkMH8(c *C) {
	c.Logf("Block size: 8B")
	h.benchmarkSize(c, 8)
}
