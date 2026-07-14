package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBip32KeyPairFromBinarySeed(t *testing.T) {
	// BIP32 test vector: seed = "Satoshi"
	seed := []byte("Satoshi")
	kp := Bip32KeyPairFromBinarySeed(seed)

	assert.NotNil(t, kp.PrivateKey())
	assert.NotNil(t, kp.ChainCode())
	assert.NotEmpty(t, kp.PublicKey())
	assert.False(t, kp.IsPublicOnly())
	assert.True(t, kp.IsExtended())
}

func TestBip32KeyPairFromBinarySeedKnownVector(t *testing.T) {
	// BIP32 test vector from the spec
	// seed: 000102030405060708090a0b0c0d0e0f
	seed := hexDecode("000102030405060708090a0b0c0d0e0f")
	kp := Bip32KeyPairFromBinarySeed(seed)

	// Expected master key (from BIP32 spec)
	expectedPK := hexDecode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
	assert.Equal(t, expectedPK, kp.PrivateKey())

	expectedCC := hexDecode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
	assert.Equal(t, expectedCC, kp.ChainCode())
}

func TestBip32KeyPairToTLVRoundtrip(t *testing.T) {
	seed := []byte("test seed for roundtrip")
	original := Bip32KeyPairFromBinarySeed(seed)

	tlv := original.ToTLV(true)
	parsed, err := Bip32KeyPairFromTLV(tlv)
	require.NoError(t, err)

	assert.Equal(t, original.PrivateKey(), parsed.PrivateKey())
	assert.Equal(t, original.ChainCode(), parsed.ChainCode())
	assert.Equal(t, original.PublicKey(), parsed.PublicKey())
}

func TestBip32KeyPairToTLVWithoutPublic(t *testing.T) {
	seed := []byte("test seed")
	kp := Bip32KeyPairFromBinarySeed(seed)
	tlv := kp.ToTLV(false)

	parsed, err := Bip32KeyPairFromTLV(tlv)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey(), parsed.PrivateKey())
	assert.Equal(t, kp.ChainCode(), parsed.ChainCode())
}

func TestBip32KeyPairEthereumAddress(t *testing.T) {
	seed := []byte("ethereum address test")
	kp := Bip32KeyPairFromBinarySeed(seed)
	addr := kp.ToEthereumAddress()
	assert.Equal(t, 20, len(addr))
}

func TestBip32KeyPairIsPublicOnly(t *testing.T) {
	// Create a keypair with only a public key
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	for i := 1; i < 65; i++ {
		pubKey[i] = 0x42
	}

	kp := newBip32KeyPair(nil, nil, pubKey)
	assert.True(t, kp.IsPublicOnly())
	assert.False(t, kp.IsExtended())
}

func TestBip32KeyPairZeroize(t *testing.T) {
	seed := []byte("test seed")
	kp := Bip32KeyPairFromBinarySeed(seed)

	privKey := kp.PrivateKey()
	kp.Zeroize()

	assert.Nil(t, kp.PrivateKey())
	assert.Nil(t, kp.ChainCode())
	// Public key should remain
	assert.NotEmpty(t, kp.PublicKey())
	// The original slice should be zeroed
	allZero := true
	for _, b := range privKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.True(t, allZero)
}

func hexDecode(hex string) []byte {
	data := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			v <<= 4
			c := hex[i+j]
			if c >= '0' && c <= '9' {
				v |= c - '0'
			} else if c >= 'a' && c <= 'f' {
				v |= c - 'a' + 10
			} else if c >= 'A' && c <= 'F' {
				v |= c - 'A' + 10
			}
		}
		data[i/2] = v
	}
	return data
}
