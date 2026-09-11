package keycard

import (
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/derivationpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingChannel captures the last APDU command sent and returns a fixed OK response.
type capturingChannel struct {
	lastCmd *apdu.Command
}

func (c *capturingChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	c.lastCmd = cmd
	// Return a 32-byte shared secret (raw x-coordinate of the resulting point).
	return &apdu.Response{Sw: apdu.SwOK, Data: make([]byte, 32)}, nil
}

func TestECDH_BuildsCorrectAPDU(t *testing.T) {
	ch := &capturingChannel{}
	cs := NewCommandSet(ch)
	cs.sc = NewSecureChannelV2(nil, nil) // not open → sendProtected sends plaintext

	// Peer public key: 0x04 || X || Y (65 bytes)
	peerPub := make([]byte, 65)
	peerPub[0] = 0x04
	for i := 1; i <= 32; i++ {
		peerPub[i] = 0x11
		peerPub[i+32] = 0x22
	}

	resp, err := cs.ECDH(peerPub, "m/44'/1237'/0'/0/0")
	require.NoError(t, err)
	assert.NotNil(t, resp)
	require.NotNil(t, ch.lastCmd)

	assert.Equal(t, uint8(0x80), ch.lastCmd.Cla)
	assert.Equal(t, uint8(InsECDH), ch.lastCmd.Ins)
	assert.Equal(t, uint8(P1SignDerive), ch.lastCmd.P1)
	assert.Equal(t, uint8(P2ECDHRawSecret), ch.lastCmd.P2)

	// Data layout: peer pub (65 bytes) || path (5 * 4 = 20 bytes)
	expectedPath, err := derivationpath.KeyPathFromString("m/44'/1237'/0'/0/0")
	require.NoError(t, err)
	assert.Equal(t, 65+len(expectedPath.Data()), len(ch.lastCmd.Data))
	assert.Equal(t, peerPub, ch.lastCmd.Data[:65])
	assert.Equal(t, expectedPath.Data(), ch.lastCmd.Data[65:])
}

func TestECDH_RejectsNonAbsolutePath(t *testing.T) {
	ch := &capturingChannel{}
	cs := NewCommandSet(ch)
	cs.sc = NewSecureChannelV2(nil, nil)

	peerPub := make([]byte, 65)
	peerPub[0] = 0x04

	// A relative path (source != MASTER) must be rejected host-side.
	_, err := cs.ECDH(peerPub, "./44'/1237'/0'/0/0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute path")
	assert.Nil(t, ch.lastCmd)
}

func TestECDH_RejectsBadPeerKey(t *testing.T) {
	ch := &capturingChannel{}
	cs := NewCommandSet(ch)
	cs.sc = NewSecureChannelV2(nil, nil)

	// Wrong length
	_, err := cs.ECDH(make([]byte, 10), "m/44'/1237'/0'/0/0")
	require.Error(t, err)

	// Wrong tag
	peerPub := make([]byte, 65)
	peerPub[0] = 0x02
	_, err = cs.ECDH(peerPub, "m/44'/1237'/0'/0/0")
	require.Error(t, err)
	assert.Nil(t, ch.lastCmd)
}

func TestECDHRaw_AppendsPath(t *testing.T) {
	ch := &capturingChannel{}
	cs := NewCommandSet(ch)
	cs.sc = NewSecureChannelV2(nil, nil)

	peerPub := make([]byte, 65)
	peerPub[0] = 0x04

	rawPath := []byte{0x80, 0x00, 0x00, 0x2C} // 44'
	resp, err := cs.ECDHRaw(peerPub, rawPath)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	require.NotNil(t, ch.lastCmd)

	assert.Equal(t, uint8(P1SignDerive), ch.lastCmd.P1)
	assert.Equal(t, uint8(P2ECDHRawSecret), ch.lastCmd.P2)
	assert.Equal(t, 65+len(rawPath), len(ch.lastCmd.Data))
	assert.Equal(t, rawPath, ch.lastCmd.Data[65:])
}

func TestECDH_PathPrefixes(t *testing.T) {
	// NIP-44: m/44'/1237'
	nip44, err := derivationpath.KeyPathFromString("m/44'/1237'")
	require.NoError(t, err)
	assert.Equal(t, NIP44Prefix, nip44.Data())

	// EIP-1581: m/43'/60'/1581'
	eip1581, err := derivationpath.KeyPathFromString("m/43'/60'/1581'")
	require.NoError(t, err)
	assert.Equal(t, EIP1581Prefix, eip1581.Data())

	// These are the only prefixes the card accepts for ECDH.
	assert.Equal(t, 8, len(NIP44Prefix))
	assert.Equal(t, 12, len(EIP1581Prefix))
}

func TestECDH_ConstantValues(t *testing.T) {
	assert.Equal(t, uint8(0xC5), uint8(InsECDH))
	assert.Equal(t, uint8(0x00), uint8(P2ECDHRawSecret))
	assert.Equal(t, uint8(0x04), uint8(UncompressedPointTag))
	assert.Equal(t, 65, Secp256k1UncompressedPubKeySize)
	assert.Equal(t, uint8(0x01), uint8(P1SignDerive))
}
