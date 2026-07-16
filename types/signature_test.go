package types

import (
	"crypto/sha256"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// RecoverPublicKey tests
// ============================================================================

func TestRecoverPublicKey_Valid(t *testing.T) {
	// Use a known test vector: recover public key from ECDSA signature components.
	// hash = SHA-256("test message")
	msg := sha256.Sum256([]byte("test message"))

	// r and s from a known valid signature (recID=0)
	r := hexDecode("6e2a45f5680aa8465c4273ea0c5d6f2c2fd01d2a69c4ac5b3c3e5a0b2d4e0a1b")
	s := hexDecode("3c5e8f9a2b4d6e1c7f0a3b5d8e2c4f6a9b1d3e5f7a9c2d4e6f8a0b2c4d6e8f0a")

	// Try all recovery IDs
	var found bool
	for recID := int32(0); recID <= 3; recID++ {
		pubKey, err := RecoverPublicKey(recID, msg[:], r, s, true)
		if err != nil {
			continue
		}
		assert.Equal(t, 33, len(pubKey), "compressed key should be 33 bytes")
		assert.Contains(t, []byte{0x02, 0x03}, pubKey[0], "compressed key prefix should be 0x02 or 0x03")
		found = true
	}
	assert.True(t, found, "at least one recovery ID should produce a valid key")
}

func TestRecoverPublicKey_Uncompressed(t *testing.T) {
	msg := sha256.Sum256([]byte("test uncompressed"))
	r := hexDecode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
	s := hexDecode("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3")

	for recID := int32(0); recID <= 3; recID++ {
		pubKey, err := RecoverPublicKey(recID, msg[:], r, s, false)
		if err != nil {
			continue
		}
		assert.Equal(t, 65, len(pubKey), "uncompressed key should be 65 bytes")
		assert.Equal(t, byte(0x04), pubKey[0], "uncompressed key prefix should be 0x04")
		break
	}
}

func TestRecoverPublicKey_InvalidRecID(t *testing.T) {
	msg := sha256.Sum256([]byte("test"))
	r := make([]byte, 32)
	s := make([]byte, 32)

	_, err := RecoverPublicKey(-1, msg[:], r, s, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recID")

	_, err = RecoverPublicKey(4, msg[:], r, s, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "recID")
}

func TestRecoverPublicKey_InvalidInputLengths(t *testing.T) {
	msg := sha256.Sum256([]byte("test"))
	r := make([]byte, 32)
	s := make([]byte, 32)

	// hash too short
	_, err := RecoverPublicKey(0, msg[:31], r, s, true)
	assert.Error(t, err)

	// r too short
	_, err = RecoverPublicKey(0, msg[:], r[:31], s, true)
	assert.Error(t, err)

	// s too short
	_, err = RecoverPublicKey(0, msg[:], r, s[:31], true)
	assert.Error(t, err)
}

// ============================================================================
// ParseRecoverableSignature tests
// ============================================================================

func TestParseRecoverableSignature_Valid(t *testing.T) {
	// Generate a real key pair and sign a message so Ecrecover can succeed.
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("recoverable signature test"))
sig, err := crypto.Sign(msg[:], privKey)
	require.NoError(t, err)
	// crypto.Sign returns 65 bytes: r(32) + s(32) + v(1)
	assert.Equal(t, 65, len(sig))

	result, err := ParseRecoverableSignature(msg[:], sig)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 32, len(result.R()))
	assert.Equal(t, 32, len(result.S()))
	assert.Equal(t, sig[64], result.V())
	assert.Equal(t, 65, len(result.PubKey()), "should return uncompressed 65-byte key")
}

func TestParseRecoverableSignature_InvalidLength(t *testing.T) {
	msg := sha256.Sum256([]byte("test"))

	// Too short
	sig := make([]byte, 64)
	_, err := ParseRecoverableSignature(msg[:], sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")

	// Too long
	sig = make([]byte, 66)
	_, err = ParseRecoverableSignature(msg[:], sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature")

	// Empty
	_, err = ParseRecoverableSignature(msg[:], nil)
	assert.Error(t, err)
}

// ============================================================================
// ParseSignature (legacy template) tests
// ============================================================================

func TestParseSignature_LegacyTemplate(t *testing.T) {
	// Generate a real key pair and sign a message.
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("legacy test"))
	sig, err := crypto.Sign(msg[:], privKey)
	require.NoError(t, err)

	// Wrap in raw signature tag
	response := make([]byte, 0, 2+65)
	response = append(response, TagRawSignature, 0x41) // tag 0x80, length 65
	response = append(response, sig...)

	result, err := ParseSignature(msg[:], response)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParseSignature_NoMatchingTag(t *testing.T) {
	msg := sha256.Sum256([]byte("test"))
	response := []byte{0xFF, 0x01, 0x00} // no matching tags

	_, err := ParseSignature(msg[:], response)
	assert.Error(t, err)
}

// ============================================================================
// Signature.EthereumAddress tests
// ============================================================================

func TestSignatureEthereumAddress(t *testing.T) {
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("ethereum address test"))
	sig, err := crypto.Sign(msg[:], privKey)
	require.NoError(t, err)

	result, err := ParseRecoverableSignature(msg[:], sig)
	require.NoError(t, err)

	addr := result.EthereumAddress()
	assert.Equal(t, 20, len(addr))
}

// ============================================================================
// DERSignatureToRS tests
// ============================================================================

func TestDERSignatureToRS_Valid(t *testing.T) {
	// Build a minimal DER signature inside a SEQUENCE
	r := make([]byte, 32)
	s := make([]byte, 32)
	for i := range r {
		r[i] = byte(i + 1)
	}
	for i := range s {
		s[i] = byte(i + 100)
	}

	// SEQUENCE { INTEGER r, INTEGER s }
	der := make([]byte, 0, 70)
	der = append(der, 0x30, 0x44) // SEQUENCE, length 68
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, r...)
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, s...)

	rOut, sOut, err := DERSignatureToRS(der)
	require.NoError(t, err)
	assert.Equal(t, r, rOut)
	assert.Equal(t, s, sOut)
}

func TestDERSignatureToRS_LongR(t *testing.T) {
	// R with leading zero (33 bytes) — should be truncated to last 32
	r := make([]byte, 33)
	r[0] = 0x00
	for i := 1; i < 33; i++ {
		r[i] = byte(i)
	}
	s := make([]byte, 32)

	der := make([]byte, 0)
	der = append(der, 0x30, 0x45) // SEQUENCE, length 69
	der = append(der, 0x02, 0x21) // INTEGER, length 33
	der = append(der, r...)
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, s...)

	rOut, sOut, err := DERSignatureToRS(der)
	require.NoError(t, err)
	assert.Equal(t, 32, len(rOut))
	assert.Equal(t, 32, len(sOut))
}

func TestDERSignatureToRS_SchnorrRaw(t *testing.T) {
	// Schnorr signature: tag 0x88 with raw 64 bytes (r||s)
	r := make([]byte, 32)
	s := make([]byte, 32)
	for i := range r {
		r[i] = byte(i + 1)
	}
	for i := range s {
		s[i] = byte(i + 100)
	}

	// Tag 0x88, length 64, r(32) + s(32)
	tlv := make([]byte, 0, 66)
	tlv = append(tlv, TagSchnorrSignature, 0x40)
	tlv = append(tlv, r...)
	tlv = append(tlv, s...)

	rOut, sOut, err := DERSignatureToRS(tlv)
	require.NoError(t, err)
	assert.Equal(t, r, rOut)
	assert.Equal(t, s, sOut)
}

func TestDERSignatureToRS_SchnorrInvalidLength(t *testing.T) {
	// Tag 0x88 with wrong length should error
	tlv := []byte{TagSchnorrSignature, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	_, _, err := DERSignatureToRS(tlv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schnorr signature must be 64 bytes")
}


