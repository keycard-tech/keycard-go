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
// AES-CCM mode implementation (T=8, L=13, no AAD)
//
// Used by Secure Channel V2. The card firmware uses a non-standard CCM
// flags encoding (0x19 instead of RFC 3610's 0x11 for T=8, L=2).
// See: docs/secure-channel-ccm-security-review.md
// ============================================================================

const (
	ccmFlagsByte   = 0x19 // F=0, M=3, T=8, L=1, Q=2 (per card firmware spec)
	ctrFlagsByte   = 0x01 // CTR mode flags byte (per card firmware)
	ccmNonceLen    = 13
	ccmTagLen      = 8
	ccmMessageLenF = 2 // 15 - nonceLen = 2 bytes for message length in B0
)

// CcmMode implements AES-CCM (Counter with CBC-MAC) authenticated encryption.
type CcmMode struct {
	block cipher.Block
}

// NewCCM creates a new AES-CCM mode instance.
func NewCCM(block cipher.Block) *CcmMode {
	return &CcmMode{block: block}
}

// buildB0 builds the first CCM block (B0): [Flags | Nonce(13) | MessageLen(2)]
func buildB0(nonce []byte, msgLen int) []byte {
	b0 := make([]byte, 16)
	b0[0] = ccmFlagsByte
	copy(b0[1:1+ccmNonceLen], nonce)
	b0[1+ccmNonceLen] = byte(msgLen >> 8)
	b0[1+ccmNonceLen+1] = byte(msgLen)
	return b0
}

// buildCtrBlock builds a CCM counter block: [CTR_Flags | Nonce(13) | Counter(2)]
func buildCtrBlock(nonce []byte, counter uint16) []byte {
	block := make([]byte, 16)
	block[0] = ctrFlagsByte
	copy(block[1:1+ccmNonceLen], nonce)
	block[14] = byte(counter >> 8)
	block[15] = byte(counter)
	return block
}

// computeCBCMAC computes the CBC-MAC for CCM mode over data blocks.
// No AAD is processed.
func (c *CcmMode) computeCBCMAC(data []byte, b0 []byte) []byte {
	// Start with B0
	block := make([]byte, 16)
	copy(block, b0)
	c.block.Encrypt(block, block)

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
	return block[:ccmTagLen]
}

// ctrCrypt builds a CTR stream starting at counter=0 and XORs it with data.
// When data is laid out as [tag | payload], counter 0 encrypts/decrypts the
// tag and counters 1..N encrypt/decrypt the payload — matching the card's
// aesCcmCtrCrypt behaviour in a single pass.
func (c *CcmMode) ctrCrypt(nonce, data []byte) {
	ctrBlock := buildCtrBlock(nonce, 0)
	counter := cipher.NewCTR(c.block, ctrBlock)
	counter.XORKeyStream(data, data)
}

// EncryptAndAuthenticate encrypts plaintext and returns ciphertext with
// authentication tag appended. The output is ciphertext || tag (8 bytes).
// No AAD is supported.
func (c *CcmMode) EncryptAndAuthenticate(nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != ccmNonceLen {
		return nil, fmt.Errorf("ccm: nonce length %d != expected %d", len(nonce), ccmNonceLen)
	}
	if len(plaintext) > 0xFFFE {
		return nil, errors.New("ccm: plaintext too long (>65534 bytes)")
	}

	// Build the first CCM block (B0): [Flags | Nonce(13) | MessageLen(2)]
	b0 := buildB0(nonce, len(plaintext))

	// Compute CBC-MAC over plaintext
	tag := c.computeCBCMAC(plaintext, b0)

	// Encrypt tag and plaintext in a single CTR pass.
	// Layout: [tag(8) | pad(8) | plaintext] — counter 0 encrypts the tag (padded to 16),
	// counters 1..N encrypt the data. This matches the card's aesCcmCtrCrypt.
	buf := make([]byte, 16+len(plaintext))
	copy(buf[:ccmTagLen], tag)
	// bytes 8..15 are zero (padding)
	copy(buf[16:], plaintext)
	c.ctrCrypt(nonce, buf)

	// Rearrange to [ciphertext | encrypted_tag]
	result := make([]byte, len(plaintext)+ccmTagLen)
	copy(result, buf[16:])                // ciphertext
	copy(result[len(plaintext):], buf[:ccmTagLen]) // encrypted tag
	return result, nil
}

// DecryptAndAuthenticate decrypts ciphertext and verifies the authentication
// tag. The input is ciphertext || tag (8 bytes). No AAD is supported.
func (c *CcmMode) DecryptAndAuthenticate(nonce, ciphertextWithTag []byte) ([]byte, error) {
	if len(nonce) != ccmNonceLen {
		return nil, fmt.Errorf("ccm: nonce length %d != expected %d", len(nonce), ccmNonceLen)
	}
	if len(ciphertextWithTag) < ccmTagLen {
		return nil, errors.New("ccm: ciphertext too short")
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-ccmTagLen]
	tag := ciphertextWithTag[len(ciphertextWithTag)-ccmTagLen:]

	// Decrypt tag and ciphertext in a single CTR pass.
	// Layout: [tag(8) | pad(8) | ciphertext] — counter 0 decrypts the tag (padded to 16),
	// counters 1..N decrypt the data.
	buf := make([]byte, 16+len(ciphertext))
	copy(buf[:ccmTagLen], tag)
	// bytes 8..15 are zero (padding)
	copy(buf[16:], ciphertext)
	c.ctrCrypt(nonce, buf)

	// Extract decrypted tag and plaintext
	decryptedTag := buf[:ccmTagLen]
	plaintext := buf[16:]

	// Build the first CCM block (B0) for MAC verification over plaintext
	b0 := buildB0(nonce, len(plaintext))

	// Compute expected MAC over the recovered plaintext
	expectedTag := c.computeCBCMAC(plaintext, b0)

	// Verify tag (constant-time comparison)
	if !hmac.Equal(decryptedTag, expectedTag) {
		return nil, errors.New("ccm: authentication failed")
	}

	return plaintext, nil
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

	ccm := NewCCM(block)
	return ccm.EncryptAndAuthenticate(nonce, plaintext)
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

	ccm := NewCCM(block)
	return ccm.DecryptAndAuthenticate(nonce, ciphertextWithTag)
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
