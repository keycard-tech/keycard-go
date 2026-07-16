package keycard

import (
	"errors"
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/types"
	"github.com/stretchr/testify/assert"
)

type fakeChannel struct {
	lastCmd *apdu.Command
}

func (fc *fakeChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	fc.lastCmd = cmd
	return nil, errors.New("test error")
}

func TestSecureChannelV1_Send(t *testing.T) {
	c := &fakeChannel{}
	sc := &SecureChannelV1{
		c:      c,
		encKey: hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441"),
		macKey: hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7"),
		iv:     hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5"),
		open:   true,
	}

	data := hexutils.HexToBytes("D545A5E95963B6BCED86A6AE826D34C5E06AC64A1217EFFA1415A96674A82500")

	cmd := NewCommandMutuallyAuthenticate(data)
	sc.Send(cmd)

	expectedData := "BA796BF8FAD1FD50407B87127B94F5023EF8903AE926EAD8A204F961B8A0EDAEE7CCCFE7F7F6380CE2C6F188E598E4468B7DEDD0E807C18CCBDA71A55F3E1F9A"
	assert.Equal(t, expectedData, hexutils.BytesToHex(c.lastCmd.Data))

	expectedIV := "BA796BF8FAD1FD50407B87127B94F502"
	assert.Equal(t, expectedIV, hexutils.BytesToHex(sc.iv))
}

func TestSecureChannelV1_Version(t *testing.T) {
	sc := NewSecureChannel(nil)
	assert.Equal(t, VersionV1, sc.Version())
}

func TestSecureChannelV1_IsOpen(t *testing.T) {
	sc := NewSecureChannel(nil)
	assert.False(t, sc.IsOpen())

	sc.open = true
	assert.True(t, sc.IsOpen())

	sc.Reset()
	assert.False(t, sc.IsOpen())
}

func TestSecureChannelV1_Pairing(t *testing.T) {
	sc := NewSecureChannel(nil)
	assert.Nil(t, sc.Pairing())

	pairing := types.NewPairing([32]byte{1, 2, 3}, 5)
	sc.SetPairing(pairing)
	assert.Equal(t, pairing, sc.Pairing())
	assert.Equal(t, uint8(5), sc.Pairing().Index())
}

// ============================================================================
// SecureChannelV1 session teardown tests
// ============================================================================

func TestSecureChannelV1_TransmitSendErrorClosesSession(t *testing.T) {
	c := &fakeChannel{}
	sc := NewSecureChannel(nil)
	sc.open = true
	sc.established = true
	sc.encKey = hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
	sc.macKey = hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
	sc.iv = hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5")

	cmd := apdu.NewCommand(0x80, 0xF2, 0x00, 0x00, nil)
	_, err := sc.Transmit(c, cmd)
	assert.Error(t, err)
	assert.False(t, sc.IsOpen(), "session should be closed after send error")
}

func TestSecureChannelV1_TransmitShortResponseClosesSession(t *testing.T) {
	// Channel that returns a response with data too short for decryption
	shortChannel := &shortResponseChannel{
		data: []byte{0x01, 0x02, 0x90, 0x00}, // less than 16 bytes
	}
	sc := NewSecureChannel(nil)
	sc.open = true
	sc.established = true
	sc.encKey = hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
	sc.macKey = hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
	sc.iv = hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5")

	cmd := apdu.NewCommand(0x80, 0xF2, 0x00, 0x00, nil)
	_, err := sc.Transmit(shortChannel, cmd)
	assert.Error(t, err)
	assert.False(t, sc.IsOpen(), "session should be closed after short response")
}

func TestSecureChannelV1_TransmitDecryptFailureClosesSession(t *testing.T) {
	// Channel that returns garbage data that will fail decryption
	garbageChannel := &shortResponseChannel{
		data: make([]byte, 32), // enough bytes but garbage
	}
	for i := range garbageChannel.data {
		garbageChannel.data[i] = byte(i)
	}
	// Add status word
	garbageChannel.data = append(garbageChannel.data, 0x90, 0x00)

	sc := NewSecureChannel(nil)
	sc.open = true
	sc.established = true
	sc.encKey = hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
	sc.macKey = hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
	sc.iv = hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5")

	cmd := apdu.NewCommand(0x80, 0xF2, 0x00, 0x00, nil)
	_, err := sc.Transmit(garbageChannel, cmd)
	assert.Error(t, err)
	assert.False(t, sc.IsOpen(), "session should be closed after decrypt failure")
}

func TestSecureChannelV1_ProtectedCommandErrorsAfterEstablishedAndClosed(t *testing.T) {
	sc := NewSecureChannel(nil)
	sc.established = true
	sc.open = false

	_, err := sc.ProtectedCommand(0x80, 0xF2, 0x00, 0x00, []byte{0x01})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed after an error")
}

func TestSecureChannelV1_TransmitSecurityConditionNotSatisfied(t *testing.T) {
	// Channel that returns SW 0x6982 (security condition not satisfied)
	secChannel := &shortResponseChannel{
		data: []byte{0x69, 0x82}, // SW 0x6982
	}

	sc := NewSecureChannel(nil)
	sc.open = true
	sc.established = true
	sc.encKey = hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
	sc.macKey = hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
	sc.iv = hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5")

	cmd := apdu.NewCommand(0x80, 0xF2, 0x00, 0x00, nil)
	resp, err := sc.Transmit(secChannel, cmd)
	assert.NoError(t, err) // Transmit itself succeeds
	assert.NotNil(t, resp)
	assert.False(t, sc.IsOpen(), "session should be closed after security condition not satisfied")
}

func TestSecureChannelV1_ResetClearsKeys(t *testing.T) {
	sc := NewSecureChannel(nil)
	sc.open = true
	sc.established = true
	sc.encKey = hexutils.HexToBytes("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
	sc.macKey = hexutils.HexToBytes("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
	sc.iv = hexutils.HexToBytes("627E64358FA9BDCDAD4442BD8006E0A5")

	sc.Reset()

	assert.False(t, sc.IsOpen())
	assert.Nil(t, sc.encKey)
	assert.Nil(t, sc.macKey)
	assert.Nil(t, sc.iv)
}

// shortResponseChannel is a types.Channel that returns a pre-built response.
type shortResponseChannel struct {
	data []byte
}

func (s *shortResponseChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := apdu.ParseResponse(s.data)
	return resp, err
}
