package types

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// NewPairing tests
// ============================================================================

func TestNewPairing(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5}
	p := NewPairing(key, 3)

	assert.Equal(t, key, p.Key())
	assert.Equal(t, uint8(3), p.Index())
}

// ============================================================================
// PairingFromBytes / ToBytes roundtrip tests
// ============================================================================

func TestPairingFromBytes_Valid(t *testing.T) {
	data := make([]byte, 33)
	data[0] = 5 // index
	for i := 1; i <= 32; i++ {
		data[i] = byte(i) // key
	}

	p, err := PairingFromBytes(data)
	require.NoError(t, err)
	assert.Equal(t, uint8(5), p.Index())

	expectedKey := [32]byte{}
	for i := 0; i < 32; i++ {
		expectedKey[i] = byte(i + 1)
	}
	assert.Equal(t, expectedKey, p.Key())
}

func TestPairingFromBytes_TooShort(t *testing.T) {
	_, err := PairingFromBytes([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestPairingFromBytes_Nil(t *testing.T) {
	_, err := PairingFromBytes(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestPairingToBytesRoundtrip(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = byte(i + 10)
	}
	original := NewPairing(key, 7)

	bytes := original.ToBytes()
	assert.Equal(t, 33, len(bytes))
	assert.Equal(t, byte(7), bytes[0])

	parsed, err := PairingFromBytes(bytes)
	require.NoError(t, err)
	assert.Equal(t, key, parsed.Key())
	assert.Equal(t, uint8(7), parsed.Index())
}

func TestPairingToBytesRoundtrip_ZeroIndex(t *testing.T) {
	key := [32]byte{0xFF}
	original := NewPairing(key, 0)

	bytes := original.ToBytes()
	parsed, err := PairingFromBytes(bytes)
	require.NoError(t, err)
	assert.Equal(t, key, parsed.Key())
	assert.Equal(t, uint8(0), parsed.Index())
}

// ============================================================================
// PairingFromBase64 / ToBase64 roundtrip tests
// ============================================================================

func TestPairingFromBase64_Valid(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = byte(i + 1)
	}
	original := NewPairing(key, 2)

	b64 := original.ToBase64()

	parsed, err := PairingFromBase64(b64)
	require.NoError(t, err)
	assert.Equal(t, key, parsed.Key())
	assert.Equal(t, uint8(2), parsed.Index())
}

func TestPairingFromBase64_Invalid(t *testing.T) {
	_, err := PairingFromBase64("not-valid-base64!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base64")
}

func TestPairingFromBase64_TooShortAfterDecode(t *testing.T) {
	// Valid base64 but decodes to less than 33 bytes
	b64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_, err := PairingFromBase64(b64)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestPairingToBase64Roundtrip(t *testing.T) {
	key := [32]byte{0xAA, 0xBB, 0xCC}
	original := NewPairing(key, 4)

	b64 := original.ToBase64()
	assert.NotEmpty(t, b64)

	parsed, err := PairingFromBase64(b64)
	require.NoError(t, err)
	assert.Equal(t, key, parsed.Key())
	assert.Equal(t, uint8(4), parsed.Index())
}

// ============================================================================
// Zeroize tests
// ============================================================================

func TestPairingZeroize(t *testing.T) {
	key := [32]byte{0xFF, 0xFF, 0xFF}
	p := NewPairing(key, 1)

	p.Zeroize()

	zeroed := p.Key()
	for _, b := range zeroed {
		assert.Equal(t, byte(0), b)
	}
}

func TestPairingZeroize_NilSafe(t *testing.T) {
	p := NewPairing([32]byte{}, 0)
	// Should not panic
	p.Zeroize()
}
