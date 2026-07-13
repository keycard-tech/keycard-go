package keycard

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSelectChannel is a mock APDU channel for testing CommandSet auto-detection.
type mockSelectChannel struct {
	responses []*apdu.Response
	index     int
}

func (m *mockSelectChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	if m.index >= len(m.responses) {
		return nil, errors.New("no more mock responses")
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

// buildSelectResponsePreInit builds a SELECT response for an uninitialized card.
// Only contains TLV_PUB_KEY (0x80) with a valid uncompressed public key.
func buildSelectResponsePreInit(pubKey []byte) *apdu.Response {
	data := make([]byte, 0, 2+1+len(pubKey))
	data = append(data, 0x80, byte(len(pubKey)))
	data = append(data, pubKey...)
	return &apdu.Response{Data: data, Sw1: 0x90, Sw2: 0x00, Sw: 0x9000}
}

func TestCommandSet_NewCommandSet(t *testing.T) {
	cs := NewCommandSet(nil)
	assert.NotNil(t, cs)
	assert.Equal(t, [][33]byte{DefaultCAPublicKey}, cs.caPublicKeys)
	assert.Nil(t, cs.whitelistedKeys)
}

func TestCommandSet_NewCommandSetWithCA(t *testing.T) {
	ca := [33]byte{0x02}
	for i := 1; i < 33; i++ {
		ca[i] = byte(i)
	}
	cs := NewCommandSetWithCA(nil, ca)
	assert.NotNil(t, cs)
	assert.Equal(t, [][33]byte{ca}, cs.caPublicKeys)
}

func TestCommandSet_NewCommandSetWithCAs(t *testing.T) {
	ca1 := [33]byte{0x02}
	ca2 := [33]byte{0x03}
	cardKey := [33]byte{0x04}
	cs := NewCommandSetWithCAs(nil, [][33]byte{ca1, ca2}, [][33]byte{cardKey})
	assert.NotNil(t, cs)
	assert.Equal(t, [][33]byte{ca1, ca2}, cs.caPublicKeys)
	assert.Equal(t, [][33]byte{cardKey}, cs.whitelistedKeys)
}

func TestCommandSet_SecureChannelVersion_NoSelect(t *testing.T) {
	cs := NewCommandSet(nil)
	version, ok := cs.SecureChannelVersion()
	assert.False(t, ok)
	_ = version
}

func TestCommandSet_PairingPasswordToSecret(t *testing.T) {
	secret1 := PairingPasswordToSecret("test_password")
	secret2 := PairingPasswordToSecret("test_password")
	secret3 := PairingPasswordToSecret("different_password")

	assert.Equal(t, secret1, secret2, "same password should produce same secret")
	assert.NotEqual(t, secret1, secret3, "different passwords should produce different secrets")
	assert.Equal(t, 32, len(secret1), "secret should be 32 bytes")
}

func TestCommandSet_SetPairingInfo(t *testing.T) {
	cs := NewCommandSet(nil)
	cs.SetPairingInfo([]byte{1, 2, 3}, 5)
	assert.NotNil(t, cs.PairingInfo)
	assert.Equal(t, 5, cs.PairingInfo.Index)
}

func TestParseMnemonicResponse(t *testing.T) {
	data := make([]byte, 0)
	for _, idx := range []int{12, 3456, 7890} {
		data = append(data, byte(idx>>8), byte(idx))
	}

	indexes, err := parseMnemonicResponse(data)
	require.NoError(t, err)
	assert.Equal(t, []int{12, 3456, 7890}, indexes)
}

func TestCommandSet_BuildInitData(t *testing.T) {
	cs := NewCommandSet(nil)

	// Basic: PIN || PUK || shared_secret
	data := cs.buildInitData("123456", "123456789012", []byte{0xAB, 0xCD}, nil, 0, 0)
	expected := make([]byte, 0, len("123456")+len("123456789012")+2)
	expected = append(expected, []byte("123456")...)
	expected = append(expected, []byte("123456789012")...)
	expected = append(expected, 0xAB, 0xCD)
	assert.Equal(t, expected, data)

	// With retries
	data = cs.buildInitData("123456", "123456789012", []byte{0xAB}, nil, 5, 10)
	expected = make([]byte, 0, 20)
	expected = append(expected, []byte("123456")...)
	expected = append(expected, []byte("123456789012")...)
	expected = append(expected, 0xAB, 0x05, 0x0A)
	assert.Equal(t, expected, data)

	// With alt PIN
	altPin := "654321"
	data = cs.buildInitData("123456", "123456789012", []byte{}, &altPin, 0, 0)
	expected = make([]byte, 0, 30)
	expected = append(expected, []byte("123456")...)
	expected = append(expected, []byte("123456789012")...)
	expected = append(expected, 0x00, 0x00)
	expected = append(expected, []byte(altPin)...)
	assert.Equal(t, expected, data)
}

func TestCommandSet_IsSecureChannelV2(t *testing.T) {
	cs := NewCommandSet(nil)
	cs.ApplicationInfo = &types.ApplicationInfo{}

	cs.ApplicationInfo.Version = []byte{0x03, 0x00}
	assert.False(t, cs.isSecureChannelV2())

	cs.ApplicationInfo.Version = []byte{0x04, 0x00}
	assert.True(t, cs.isSecureChannelV2())

	cs.ApplicationInfo.Version = []byte{0x04, 0x02}
	assert.True(t, cs.isSecureChannelV2())

	cs.ApplicationInfo.Version = []byte{0x05, 0x00}
	assert.True(t, cs.isSecureChannelV2())
}

func TestWrongPINError(t *testing.T) {
	err := &WrongPINError{RemainingAttempts: 3}
	assert.Contains(t, err.Error(), "wrong pin")
	assert.Contains(t, err.Error(), "3")
}

func TestWrongPUKError(t *testing.T) {
	err := &WrongPUKError{RemainingAttempts: 5}
	assert.Contains(t, err.Error(), "wrong puk")
	assert.Contains(t, err.Error(), "5")
}

// Test that the new command builders produce correct APDUs
func TestNewCommandBuilders(t *testing.T) {
	t.Run("LoadLEEKey", func(t *testing.T) {
		seed := []byte{0x01, 0x02, 0x03}
		cmd := NewCommandLoadLEEKey(seed)
		assert.Equal(t, uint8(0xD0), cmd.Ins)
		assert.Equal(t, uint8(P1LoadKeyLEE), cmd.P1)
		assert.Equal(t, seed, cmd.Data)
	})

	t.Run("ExportLEE", func(t *testing.T) {
		path := []byte{0x00, 0x00, 0x00, 0x2C} // m/44
		cmd := NewCommandExportLEE(0x00, path)
		assert.Equal(t, uint8(InsExportLEE), cmd.Ins)
		assert.Equal(t, uint8(0x00), cmd.P1)
		assert.Equal(t, path, cmd.Data)
	})

	t.Run("ExportBIP85", func(t *testing.T) {
		path := []byte{0x00, 0x00, 0x00, 0x2C}
		cmd := NewCommandExportBIP85(32, path)
		assert.Equal(t, uint8(InsExportBIP85), cmd.Ins)
		assert.Equal(t, uint8(32), cmd.P1)
		assert.Equal(t, path, cmd.Data)
	})

	t.Run("StoreDataWithOffset", func(t *testing.T) {
		data := []byte{0x01, 0x02}
		cmd := NewCommandStoreDataWithOffset(0x01, data, 440) // offset 440 -> P2 = 110
		assert.Equal(t, uint8(InsStoreData), cmd.Ins)
		assert.Equal(t, uint8(0x01), cmd.P1)
		assert.Equal(t, uint8(110), cmd.P2)
		assert.Equal(t, data, cmd.Data)
	})

	t.Run("GetChallenge", func(t *testing.T) {
		cmd := NewCommandGetChallenge(32)
		assert.Equal(t, uint8(InsGetChallenge), cmd.Ins)
		assert.Equal(t, uint8(32), cmd.P1)
		assert.Empty(t, cmd.Data)
	})

	t.Run("LoadKeyBIP32", func(t *testing.T) {
		keyTLV := []byte{0xA1, 0x03, 0x80, 0x01, 0x01}
		cmd := NewCommandLoadKeyBIP32(true, keyTLV)
		assert.Equal(t, uint8(0xD0), cmd.Ins)
		assert.Equal(t, uint8(P1LoadKeyECExtended), cmd.P1)
		assert.Equal(t, keyTLV, cmd.Data)

		cmd2 := NewCommandLoadKeyBIP32(false, keyTLV)
		assert.Equal(t, uint8(P1LoadKeyEC), cmd2.P1)
	})
}

func TestAppVersionParsing(t *testing.T) {
	info := &types.ApplicationInfo{}

	info.Version = []byte{0x01, 0x00}
	assert.Equal(t, uint16(0x0100), info.AppVersion())
	assert.Equal(t, "1.0", info.AppVersionString())

	info.Version = []byte{0x04, 0x02}
	assert.Equal(t, uint16(0x0402), info.AppVersion())
	assert.Equal(t, "4.2", info.AppVersionString())

	info.Version = []byte{}
	assert.Equal(t, uint16(0), info.AppVersion())
}

func TestPINRetries(t *testing.T) {
	info := &types.ApplicationInfo{
		Version:   []byte{0x04, 0x02},
		AppStatus: 0x1D, // initialized (0x10) + 13 retries (0x0D)
	}

	retries, ok := info.PINRetries()
	assert.True(t, ok)
	assert.Equal(t, uint8(13), retries)

	// V3 card should not report PIN retries
	info.Version = []byte{0x03, 0x00}
	retries, ok = info.PINRetries()
	assert.False(t, ok)
	assert.Equal(t, uint8(0), retries)
}

// Test that binary.BigEndian encoding is used for mnemonic indices
func TestMnemonicIndexEncoding(t *testing.T) {
	// Simulate card response with 3 mnemonic indices
	data := make([]byte, 6)
	binary.BigEndian.PutUint16(data[0:2], 1234)
	binary.BigEndian.PutUint16(data[2:4], 5678)
	binary.BigEndian.PutUint16(data[4:6], 9012)

	indexes, err := parseMnemonicResponse(data)
	require.NoError(t, err)
	assert.Equal(t, []int{1234, 5678, 9012}, indexes)
}

func TestCommandSet_PreInitSelect(t *testing.T) {
	// Test that selecting an uninitialized card works
	// and does not create a secure channel (no public key to derive from)
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	// Fill with zeros — GenerateSecret will fail, but pre-init cards
	// have empty public keys in practice

	// Use empty pub key (pre-init state)
	resp := &apdu.Response{
		Data: []byte{0x80, 0x00}, // empty public key
		Sw:   0x9000,
	}
	ch := &mockSelectChannel{responses: []*apdu.Response{resp}}
	cs := NewCommandSet(ch)

	err := cs.Select()
	require.NoError(t, err)

	assert.False(t, cs.ApplicationInfo.Initialized)
	// Pre-init cards have no secure channel capability (empty pub key)
	assert.False(t, cs.ApplicationInfo.HasSecureChannelCapability())
}

func TestCommandSet_SendProtected_NotOpen(t *testing.T) {
	// When the secure channel is not open, sendProtected should send plaintext
	ch := &mockSelectChannel{responses: []*apdu.Response{
		{Data: []byte{0x01, 0x02}, Sw: 0x9000},
	}}

	cs := NewCommandSet(ch)
	cs.sc = NewSecureChannelV2(nil, nil)

	resp, err := cs.sendProtected(0xC0, 0x01, 0x00, []byte{0xDE, 0xAD})
	require.NoError(t, err)
	assert.Equal(t, uint16(0x9000), resp.Sw)
	assert.Equal(t, []byte{0x01, 0x02}, resp.Data)
}

func TestCommandSet_FactoryReset(t *testing.T) {
	ch := &mockSelectChannel{responses: []*apdu.Response{
		{Sw: 0x9000},
	}}
	cs := NewCommandSet(ch)

	err := cs.FactoryReset()
	require.NoError(t, err)
	assert.Equal(t, 1, ch.index)
}

func TestErrNoAvailablePairingSlots(t *testing.T) {
	assert.Contains(t, ErrNoAvailablePairingSlots.Error(), "no available pairing slots")
}

func TestErrBadChecksumSize(t *testing.T) {
	assert.Contains(t, ErrBadChecksumSize.Error(), "bad checksum size")
}
