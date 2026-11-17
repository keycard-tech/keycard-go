package globalplatform

import (
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/identifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AES-128/S8 SCP03 keys and transcript of the fixture
// Samsung/OpenSCP-Java testdata/SmartCardScp03Aes128S8ModeEmulation.java (Apache-2.0).
const (
	samsungEncKey        = "1D72CD9283FD55162722C6BEAA4DC187"
	samsungMacKey        = "F4932BA02FFC3098D172790099D28382"
	samsungDekKey        = "B4BDC610C3F6793708FF1132E2C5BF60"
	samsungHostChallenge = "06F85B77251BF794"
	samsungInitUpdate    = "A1A012430585513120853003709CE033FA78E6B10DDC2DBE8974C8B0DE00082A9000"
)

func keySetHex(version byte, enc, mac, dek string) KeySet {
	return NewSCP03KeySet(version, hexutils.MustHexToBytes(enc), hexutils.MustHexToBytes(mac), hexutils.MustHexToBytes(dek))
}

func TestNewSession(t *testing.T) {
	key := hexutils.MustHexToBytes("404142434445464748494a4b4c4d4e4f")

	raw := hexutils.MustHexToBytes("000002650183039536622002000de9c62ba1c4c8e55fcb91b6654ce49000")
	resp, err := apdu.ParseResponse(raw)
	require.NoError(t, err)

	hostChallenge := hexutils.MustHexToBytes("f0467f908e5ca23f")
	session, err := NewSession(NewSCP02KeySet(key), resp, hostChallenge, LevelCMAC)
	require.NoError(t, err)

	assert.Equal(t, SCPVersion02, session.Protocol())
	assert.Equal(t, hostChallenge, session.HostChallenge())
	assert.Equal(t, hexutils.MustHexToBytes("000de9c62ba1c4c8"), session.CardChallenge())
	assert.NotNil(t, session.Keys())
}

func TestNewSession_BadResponse(t *testing.T) {
	key := hexutils.MustHexToBytes("404142434445464748494a4b4c4d4e4f")

	tests := []struct {
		name string
		raw  string
	}{
		{"security condition not satisfied", "01026982"},
		{"authentication method blocked", "01026983"},
		{"short data", "01029000"},
		{"unsupported scp version", "000002650183039536622001000de9c62ba1c4c8e55fcb91b6654ce49000"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(test.raw))
			require.NoError(t, err)

			_, err = NewSession(NewSCP02KeySet(key), resp, []byte{}, LevelCMAC)
			assert.Error(t, err)
		})
	}
}

func TestNewSession_BadCryptogram(t *testing.T) {
	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(samsungInitUpdate))
	require.NoError(t, err)

	wrong := keySetHex(0x30, samsungEncKey, samsungMacKey[:len(samsungMacKey)-2]+"00", samsungDekKey)
	_, err = NewSession(wrong, resp, hexutils.MustHexToBytes(samsungHostChallenge), LevelFull)
	assert.ErrorIs(t, err, errBadCryptogram)
}

// The card reports the protocol it negotiated, so a SCP02 key set cannot open a SCP03
// session and the other way around.
func TestNewSession_ProtocolMismatch(t *testing.T) {
	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(samsungInitUpdate))
	require.NoError(t, err)

	_, err = NewSession(NewSCP02KeySet(hexutils.MustHexToBytes(samsungEncKey)), resp, hexutils.MustHexToBytes(samsungHostChallenge), LevelCMAC)
	assert.Error(t, err)
}

func TestNewSession_SCP03(t *testing.T) {
	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(samsungInitUpdate))
	require.NoError(t, err)

	session, err := NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, hexutils.MustHexToBytes(samsungHostChallenge), LevelFull)
	require.NoError(t, err)

	assert.Equal(t, SCPVersion03, session.Protocol())
	assert.Equal(t, byte(0x30), session.KeyVersion())
	assert.Equal(t, byte(0x70), session.IParameter())
	assert.Equal(t, LevelFull, session.SecurityLevel())
	assert.Equal(t, hexutils.MustHexToBytes("9CE033FA78E6B10D"), session.CardChallenge())
	assert.Nil(t, session.Keys(), "a SCP03 session has no SCP02 keys")
}

func TestNewSession_SCP03_S16(t *testing.T) {
	// Samsung/OpenSCP-Java testdata/SmartCardScp03Aes128S16ModeEmulation.java.
	const (
		hostChallenge = "06F85B77251BF79406F85B77251BF794"
		initUpdate    = "A1A012430585513120853003710617A2C34D50B562F7DECFC3DBF58A649EF733B7486D813C92E4CA61E5102F9100082A9000"
	)

	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(initUpdate))
	require.NoError(t, err)

	session, err := NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, hexutils.MustHexToBytes(hostChallenge), LevelFull)
	require.NoError(t, err)

	assert.Equal(t, byte(0x71), session.IParameter())
	assert.Equal(t, hexutils.MustHexToBytes("0617A2C34D50B562F7DECFC3DBF58A64"), session.CardChallenge())
}

func TestNewSession_SCP03_JCOP4(t *testing.T) {
	// Real JCOP4 card dump imported by PeculiarVentures/scp from GlobalPlatformPro
	// nextgen/src/test/resources/scp03-init-update-jcop4.dump, default AES keys.
	const (
		hostChallenge = "0102030405060708"
		initUpdate    = "00003244342976208448010370734ECDCA19E446A30BC253BCE97DB9910004369000"
	)

	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(initUpdate))
	require.NoError(t, err)

	key := identifiers.GlobalPlatformDefaultKey
	session, err := NewSession(NewSCP03KeySet(0, key, key, key), resp, hexutils.MustHexToBytes(hostChallenge), LevelCMAC)
	require.NoError(t, err)

	assert.Equal(t, byte(0x01), session.KeyVersion())
}

// A card configured for S16 does not accept the challenge length of a S8 host, and the
// key set must not be tried again with the wrong length.
func TestNewSession_SCP03_WrongChallengeLength(t *testing.T) {
	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(samsungInitUpdate))
	require.NoError(t, err)

	_, err = NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, make([]byte, 16), LevelCMAC)
	assert.Error(t, err)
}

func TestNewSession_SCP03_CardWithoutResponseSupport(t *testing.T) {
	// Same response with the R-MAC bits of the "i" parameter cleared.
	raw := hexutils.MustHexToBytes(samsungInitUpdate)
	raw[12] = 0x10

	resp, err := apdu.ParseResponse(raw)
	require.NoError(t, err)

	_, err = NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, hexutils.MustHexToBytes(samsungHostChallenge), LevelFull)
	assert.Error(t, err)

	_, err = NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, hexutils.MustHexToBytes(samsungHostChallenge), LevelCMAC)
	assert.NoError(t, err)
}

func TestNewSession_SCP02_RejectsEncryptionLevels(t *testing.T) {
	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes("000002650183039536622002000de9c62ba1c4c8e55fcb91b6654ce49000"))
	require.NoError(t, err)

	_, err = NewSession(NewSCP02KeySet(hexutils.MustHexToBytes("404142434445464748494a4b4c4d4e4f")), resp, make([]byte, 8), LevelCDECMAC)
	assert.Error(t, err)
}
