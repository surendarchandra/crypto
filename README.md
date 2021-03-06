# crypto

This package accelerates crypto functions using [Intel ISA-L crypto library](https://github.com/01org/isa-l_crypto) (must be installed separately). The ISA-l library uses AES-NI (for cryptography) and SSE4.1 or AVX instructions (for hashing_; the package will fail if these instructions are unavailable (they have been available since Westmere - 2010).

* It supports AES-CBC-128, AES-CBC-192 and AES-CBC-256 using Go's crypto API.
* It supports GCM-128 and GCM-256 using Go's crypto API. It does not support non-standard nonce (which was deprecated in Go) or GCM-192.
* It also introduces XTS mode of operation. The XTS module follows Go's crypto structure. SetIV must be specified before each crypto operation to set the tweak.

## Example
    package main

    import (
        "github.com/surendarchandra/crypto/aes"
        "github.com/surendarchandra/crypto/cipher"	
    )

    func main() {
        var key, cipherText, plainText []byte

	block, err := aes.NewCipher(key)

	x := cipher.NewXTSEncryptor(block)

	x.SetIV(vector.tweak)
	err = x.Encrypt(cipherText, plainText)
	err = x.Decrypt(plainText, cipherText)
    }

## Performance

Performance tests were run using Go's test benchmarks. We used a iMac (Late 2013) using 3.5GHz Intel i7 core processor running MacOS High Sierra. Go was version 1.8.4 and ISA-l_crypt is version v2.20.0.
Understand the slow performance of GCM is a TODO item.

| Mode  | Operation | Go Builtin  (MB/s) | This package (MB/s) | Percentage change |
|-------|-----------|--------------------|---------------------|----------|
| CBC-128 | Encrypt | 475.21             | 821.78              | 73%         |
| CBC-128 | Decrypt | 486.97             | 5120.95             | 951%         | 
| CBC-256 | Encrypt | 387.88             | 595.80              | 54%         | 
| CBC-256 | Decrypt | 272.90             | 3761.31             | 1278%         |
| GCM-128 | Seal    | 2264.05            | 2135.03             | -6%         |
| GCM-128 | Open    | 2134.16            | 2051.61             | -4%         |
| GCM-256 | Seal    | 1982.17            | 1861.90             | -6%         |
| GCM-256 | Open    | 1809.33            | 1875.16             | 4%         |
| XTS-128 | Encrypt |                    | 4555.22             |          |
| XTS-128 | Decrypt |                    | 4531.29             |          |
| XTS-256 | Encrypt |                    | 3626.21             |          |
| XTS-256 | Decrypt |                    | 3626.95             |          |

# Multihash SHA1
Multihash is described in
    "Multi-Hash: A Family of Cryptographic Hash Algorithm Extensions"
      - Sean Gulley, Vinodh Gopal, Jim Guilford, Kirk Yap, Wajdi Feghali, Intel.

The data is SHA1'd in parallel and the resulting hashes are finally SHA1'd.
The hash value produced is not the same as with SHA1; however it is fast.
This hashing function is useful for cases where cryptographic nature of
SHA1 is useful (though binary comptabilitiy isn't important). E.g., hash
data to randomize it.

## Hash Performance:
 - 3.5GHz Intel Core 7 (last 2013), running Mac OSX High Sierra.
 - SHA1 performance was measured using 'go test -test.bench .' on the Go source tree.

| Buffer Size | SHA1 (MB/s) | MSHA1 (MB/s) |
|-------------|-------------|--------------|
|    8 B      |   44.2      | 3.55         |
|  320 B      |  478.53     | 142.58       |
|    1 KiB    |  787.20     | 394.46       |
|    4 KiB    |  974.68     | 1157.37      |
|    8 KiB    | 1008.99     | 1746.71      |
|   16 KiB    | 1034.76     | 2729.45      |

