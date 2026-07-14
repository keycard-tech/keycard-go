package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToEthereumAddressLength(t *testing.T) {
	// Use a dummy 65-byte public key
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		pubKey[i] = 0x42
	}
	addr := ToEthereumAddress(pubKey)
	assert.Equal(t, 20, len(addr))
}

func TestToEthereumAddressKnownVector(t *testing.T) {
	// Public key from Ethereum yellow paper test vector
	// Keccak-256 of pubkey[1:] = 8c9564d6883a96096c8469d63e9003153d9a39d3f57b126b0c38513d5e289c3e
	// Address = last 20 bytes
	pubKey := hexDecode("0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6")
	addr := ToEthereumAddress(pubKey)
	// Expected: 3e9003153d9a39d3f57b126b0c38513d5e289c3e
	expected := hexDecode("3e9003153d9a39d3f57b126b0c38513d5e289c3e")
	assert.Equal(t, expected, addr[:])
}

func TestToEthereumAddressShortInput(t *testing.T) {
	addr := ToEthereumAddress([]byte{0x04})
	assert.Equal(t, 20, len(addr))
	// Should return all zeros for input < 2 bytes
	for _, b := range addr[:] {
		assert.Equal(t, byte(0), b)
	}
}
