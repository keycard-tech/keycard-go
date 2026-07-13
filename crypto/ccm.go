package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// ============================================================================
// AES-CCM mode implementation (RFC 3610, RFC 5116)
// ============================================================================

// CcmMode implements AES-CCM (Counter with CBC-MAC) authenticated encryption.
type CcmMode struct {
	block    cipher.Block
	nonceLen int
	tagLen   int
}

// NewCCM creates a new AES-CCM mode instance.
// nonceLen must be 7..13 (inclusive), tagLen must be 4, 6, 8, 12, or 16.
func NewCCM(block cipher.Block, nonceLen, tagLen int) (*CcmMode, error) {
	if nonceLen < 7 || nonceLen > 13 {
		return nil, fmt.Errorf("ccm: invalid nonce length %d (must be 7..13)", nonceLen)
	}
	if tagLen != 4 && tagLen != 6 && tagLen != 8 && tagLen != 12 && tagLen != 16 {
		return nil, fmt.Errorf("ccm: invalid tag length %d (must be 4, 6, 8, 12, or 16)", tagLen)
	}
	return &CcmMode{
		block:    block,
		nonceLen: nonceLen,
		tagLen:   tagLen,
	}, nil
}

// EncryptAndAuthenticate encrypts plaintext and returns ciphertext with authentication tag appended.
// The output is ciphertext || tag.
func (c *CcmMode) EncryptAndAuthenticate(nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != c.nonceLen {
		return nil, fmt.Errorf("ccm: nonce length %d != expected %d", len(nonce), c.nonceLen)
	}
	if len(plaintext) > 0xFFFE {
		return nil, errors.New("ccm: plaintext too long (>65534 bytes)")
	}

	m := 15 - c.nonceLen // length field size in bytes

	// Build the first CCM block (B0)
	flag := byte(0)
	if len(aad) > 0 {
		flag |= 1 << 6 // A-data flag
	}
	flag |= byte(c.tagLen/2 - 2) << 3 // M (tag length)
	flag |= byte(m - 1)               // L (length field size - 1)

	b0 := make([]byte, 16)
	b0[0] = flag
	copy(b0[1:1+c.nonceLen], nonce)
	// Encode plaintext length as big-endian m-byte integer
	for i := 0; i < m; i++ {
		b0[1+c.nonceLen+i] = byte(len(plaintext) >> (8 * (m - 1 - i)))
	}

	// Compute CBC-MAC
	tag, err := c.computeCBCMAC(aad, plaintext, b0)
	if err != nil {
		return nil, err
	}

	// Encrypt with CTR mode
	ciphertext := make([]byte, len(plaintext))
	if len(plaintext) > 0 {
		ctrBlock := make([]byte, 16)
		copy(ctrBlock[:c.nonceLen], nonce)
		ctrBlock[15] = 1 // Counter starts at 1

		counter := cipher.NewCTR(c.block, ctrBlock)
		counter.XORKeyStream(ciphertext, plaintext)
	}

	// Append tag
	result := append(ciphertext, tag...)
	return result, nil
}

// DecryptAndAuthenticate decrypts ciphertext and verifies the authentication tag.
// The input is ciphertext || tag.
func (c *CcmMode) DecryptAndAuthenticate(nonce, ciphertextWithTag, aad []byte) ([]byte, error) {
	if len(nonce) != c.nonceLen {
		return nil, fmt.Errorf("ccm: nonce length %d != expected %d", len(nonce), c.nonceLen)
	}
	if len(ciphertextWithTag) < c.tagLen {
		return nil, errors.New("ccm: ciphertext too short")
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-c.tagLen]
	receivedTag := ciphertextWithTag[len(ciphertextWithTag)-c.tagLen:]

	m := 15 - c.nonceLen

	// Decrypt with CTR mode first to recover plaintext
	plaintext := make([]byte, len(ciphertext))
	if len(ciphertext) > 0 {
		ctrBlock := make([]byte, 16)
		copy(ctrBlock[:c.nonceLen], nonce)
		ctrBlock[15] = 1

		counter := cipher.NewCTR(c.block, ctrBlock)
		counter.XORKeyStream(plaintext, ciphertext)
	}

	// Build the first CCM block (B0) for MAC verification over plaintext
	flag := byte(0)
	if len(aad) > 0 {
		flag |= 1 << 6
	}
	flag |= byte(c.tagLen/2 - 2) << 3
	flag |= byte(m - 1)

	b0 := make([]byte, 16)
	b0[0] = flag
	copy(b0[1:1+c.nonceLen], nonce)
	// Encode plaintext length as big-endian m-byte integer
	for i := 0; i < m; i++ {
		b0[1+c.nonceLen+i] = byte(len(plaintext) >> (8 * (m - 1 - i)))
	}

	// Compute expected MAC over the recovered plaintext
	expectedTag, err := c.computeCBCMAC(aad, plaintext, b0)
	if err != nil {
		return nil, err
	}

	// Verify tag (constant-time comparison)
	if !hmac.Equal(receivedTag, expectedTag) {
		return nil, errors.New("ccm: authentication failed")
	}

	return plaintext, nil
}

// computeCBCMAC computes the CBC-MAC for CCM mode.
func (c *CcmMode) computeCBCMAC(aad, data []byte, b0 []byte) ([]byte, error) {
	// Start with B0
	block := make([]byte, 16)
	copy(block, b0)
	c.block.Encrypt(block, block)

	// Process AAD (padded to 16-byte blocks)
	if len(aad) > 0 {
		aadLenBytes := make([]byte, 4)
		if len(aad) < 0x10000 {
			aadLenBytes[2] = byte(len(aad) >> 8)
			aadLenBytes[3] = byte(len(aad))
		} else {
			aadLenBytes[0] = 0xFF
			aadLenBytes[1] = 0xFE
			aadLenBytes[2] = byte(len(aad) >> 8)
			aadLenBytes[3] = byte(len(aad))
		}

		// Process full 16-byte AAD blocks
		for len(aad) >= 16 {
			for i := 0; i < 16; i++ {
				block[i] ^= aad[i]
			}
			c.block.Encrypt(block, block)
			aad = aad[16:]
		}

		// Process remaining AAD bytes + length encoding in final block
		aadBlock := make([]byte, 16)
		copy(aadBlock, aad)
		// Append AAD length encoding at the end of the block
		remaining := len(aadBlock) - len(aad)
		if remaining <= 4 {
			// Length fits in remaining space at end of block
			copy(aadBlock[len(aad):], aadLenBytes[4-remaining:])
		} else {
			// More than 4 bytes remaining; length goes in last 4 bytes
			copy(aadBlock[len(aadBlock)-4:], aadLenBytes)
		}

		for i := 0; i < 16; i++ {
			block[i] ^= aadBlock[i]
		}
		c.block.Encrypt(block, block)
	}

	// Process data blocks
	if len(data) > 0 {
		for len(data) >= 16 {
			for i := 0; i < 16; i++ {
				block[i] ^= data[i]
			}
			c.block.Encrypt(block, block)
			data = data[16:]
		}

		if len(data) > 0 {
			// Last block: XOR with data, zero-pad
			for i := 0; i < len(data); i++ {
				block[i] ^= data[i]
			}
			c.block.Encrypt(block, block)
		}
	}

	// Tag is the first tagLen bytes of the final block
	return block[:c.tagLen], nil
}

// ============================================================================
// AES-CCM convenience functions
// ============================================================================

// AESCCMEncrypt encrypts plaintext with AES-128-CCM.
// key must be 16 bytes, nonce must be 13 bytes.
// Returns ciphertext with 8-byte authentication tag appended.
func AESCCMEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("ccm: key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != 13 {
		return nil, fmt.Errorf("ccm: nonce must be 13 bytes, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ccm, err := NewCCM(block, 13, 8)
	if err != nil {
		return nil, err
	}

	return ccm.EncryptAndAuthenticate(nonce, plaintext, nil)
}

// AESCCMDecrypt decrypts ciphertext with AES-128-CCM.
// key must be 16 bytes, nonce must be 13 bytes.
// Input is ciphertext with 8-byte authentication tag appended.
func AESCCMDecrypt(key, nonce, ciphertextWithTag []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("ccm: key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != 13 {
		return nil, fmt.Errorf("ccm: nonce must be 13 bytes, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ccm, err := NewCCM(block, 13, 8)
	if err != nil {
		return nil, err
	}

	return ccm.DecryptAndAuthenticate(nonce, ciphertextWithTag, nil)
}

// ============================================================================
// HKDF-SHA256
// ============================================================================

// HKDFDerive performs HKDF-SHA256 (Extract-then-Expand) as defined in RFC 5869.
func HKDFDerive(info, salt, ikm []byte, length int) ([]byte, error) {
	h := hkdf.New(sha256.New, ikm, salt, info)
	okm := make([]byte, length)
	if _, err := h.Read(okm); err != nil {
		return nil, fmt.Errorf("hkdf: expansion failed: %w", err)
	}
	return okm, nil
}
