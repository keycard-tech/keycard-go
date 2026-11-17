package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AESBlockSize is the AES block size in bytes.
const AESBlockSize = aes.BlockSize

// Data derivation constants of the SCP03 data derivation scheme
// (GP Card Spec v2.3 Amendment D, Table 4-1).
const (
	DerivationConstantCardCryptogram byte = 0x00
	DerivationConstantHostCryptogram byte = 0x01
	DerivationConstantCardChallenge  byte = 0x02
	DerivationConstantSENC           byte = 0x04
	DerivationConstantSMAC           byte = 0x06
	DerivationConstantSRMAC          byte = 0x07
)

// CMAC returns the AES-CMAC of data as specified in NIST SP 800-38B.
func CMAC(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k1, k2 := cmacSubkeys(block)

	blocks := (len(data) + AESBlockSize - 1) / AESBlockSize
	if blocks == 0 {
		blocks = 1
	}

	x := make([]byte, AESBlockSize)
	for i := 0; i < blocks-1; i++ {
		xorInto(x, data[i*AESBlockSize:(i+1)*AESBlockSize])
		block.Encrypt(x, x)
	}

	last := make([]byte, AESBlockSize)
	if len(data) > 0 && len(data)%AESBlockSize == 0 {
		copy(last, data[len(data)-AESBlockSize:])
		xorInto(last, k1)
	} else {
		start := len(data) - len(data)%AESBlockSize
		copy(last, data[start:])
		last[len(data)-start] = 0x80
		xorInto(last, k2)
	}

	xorInto(x, last)
	block.Encrypt(x, x)

	return x, nil
}

// DeriveSCP03Key applies the SCP03 data derivation scheme (Amendment D section 4.1.5):
// KDF in counter mode (NIST SP 800-108) with AES-CMAC as PRF, used with its full
// 16-byte output. bits must be one of the values Amendment D allows for "L".
func DeriveSCP03Key(staticKey []byte, constant byte, context []byte, bits int) ([]byte, error) {
	switch bits {
	case 64, 128, 192, 256:
	default:
		return nil, fmt.Errorf("bad derived data length %d bits, expected 64, 128, 192 or 256", bits)
	}

	derived := make([]byte, 0, AESBlockSize)

	for counter := byte(1); len(derived)*8 < bits; counter++ {
		input := make([]byte, 0, 15+len(context))
		input = append(input, make([]byte, 11)...)
		input = append(input, constant, 0x00, byte(bits>>8), byte(bits), counter)
		input = append(input, context...)

		block, err := CMAC(staticKey, input)
		if err != nil {
			return nil, err
		}

		derived = append(derived, block...)
	}

	return derived[:bits/8], nil
}

// PadISO9797M2 appends a '80' byte and zero bytes until data length is a multiple
// of blockSize (ISO/IEC 9797-1 padding method 2).
func PadISO9797M2(data []byte, blockSize int) []byte {
	padded := make([]byte, len(data)+blockSize-len(data)%blockSize)
	copy(padded, data)
	padded[len(data)] = 0x80

	return padded
}

// ErrBadPadding is returned by UnpadISO9797M2 when data does not end with the
// padding method 2 pattern.
var ErrBadPadding = fmt.Errorf("bad ISO 9797-1 method 2 padding")

// UnpadISO9797M2 removes ISO/IEC 9797-1 padding method 2 from a full block multiple.
func UnpadISO9797M2(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrBadPadding
	}

	i := len(data) - 1
	for ; i >= 0 && data[i] == 0x00; i-- {
	}

	if i < 0 || data[i] != 0x80 {
		return nil, ErrBadPadding
	}

	return data[:i], nil
}

// EncryptAESBlock encrypts one block with a key, the primitive the SCP03 ICV derivation
// is built on.
func EncryptAESBlock(key, block []byte) ([]byte, error) {
	if len(block) != AESBlockSize {
		return nil, fmt.Errorf("block must be %d bytes, got %d", AESBlockSize, len(block))
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, AESBlockSize)
	cipherBlock.Encrypt(out, block)

	return out, nil
}

// EncryptAESCBC encrypts block-aligned data in AES-CBC mode.
func EncryptAESCBC(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 || len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("data must be a non-empty multiple of %d bytes", AESBlockSize)
	}

	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)

	return out, nil
}

// DecryptAESCBC decrypts block-aligned data in AES-CBC mode.
func DecryptAESCBC(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 || len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("data must be a non-empty multiple of %d bytes", AESBlockSize)
	}

	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)

	return out, nil
}

func cmacSubkeys(block cipher.Block) (k1, k2 []byte) {
	l := make([]byte, AESBlockSize)
	block.Encrypt(l, make([]byte, AESBlockSize))

	k1 = gfDouble(l)
	k2 = gfDouble(k1)

	return k1, k2
}

// gfDouble multiplies by x in GF(2^128) with the reduction polynomial x^128 + x^7 + x^2 + x + 1.
func gfDouble(in []byte) []byte {
	out := make([]byte, len(in))

	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}

	if in[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}

	return out
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
