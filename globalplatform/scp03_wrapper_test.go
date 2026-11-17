package globalplatform

import (
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samsungSession(t *testing.T, level SecurityLevel) *Session {
	t.Helper()

	resp, err := apdu.ParseResponse(hexutils.MustHexToBytes(samsungInitUpdate))
	require.NoError(t, err)

	session, err := NewSession(keySetHex(0x30, samsungEncKey, samsungMacKey, samsungDekKey), resp, hexutils.MustHexToBytes(samsungHostChallenge), level)
	require.NoError(t, err)

	return session
}

func wrapHex(t *testing.T, w secureMessagingWrapper, cmd *apdu.Command) string {
	t.Helper()

	wrapped, err := w.Wrap(cmd)
	require.NoError(t, err)

	raw, err := wrapped.Serialize()
	require.NoError(t, err)

	return hexutils.BytesToHex(raw)
}

// TestSCP03Wrapper_Transcript walks the AES-128/S8 SCP03 session of
// Samsung/OpenSCP-Java testdata/SmartCardScp03Aes128S8ModeEmulation.java (Apache-2.0):
// authentication at level 0x33, then three GET STATUS commands with C-DECRYPTION, C-MAC,
// R-MAC and R-ENCRYPTION.
func TestSCP03Wrapper_Transcript(t *testing.T) {
	session := samsungSession(t, LevelFull)

	w, err := session.newWrapper()
	require.NoError(t, err)

	authenticate, err := w.WrapAuthenticate(session.ExternalAuthenticate())
	require.NoError(t, err)

	raw, err := authenticate.Serialize()
	require.NoError(t, err)
	assert.Equal(t, "8482330010B08D6CE26B6CB3CCB411CF0296EB7B1D", hexutils.BytesToHex(raw))

	steps := []struct {
		plainCommand        string
		wrappedCommand      string
		response            string
		plainResponseStatus string
	}{
		{
			plainCommand:   "80F22000024F00",
			wrappedCommand: "84F22000185230BA64388B4A40E0B4DA5CC1DF51C285E4020D99D5AED1",
			response: "BD3292BFB1A23C4478E37292BA1EDF438770CE472FB7611FBDBD1C981A27FA4780A81A95D93C05F9C4C" +
				"94839DED0363CFEA57CE2ECFB572B26F3474DAEEBBABC202942381F9755F59000",
			plainResponseStatus: "08A00000015141434C010010A00000022020030101010000000000060100" +
				"10A0000002202003010101000000000011010005A00000024801009000",
		},
		{
			plainCommand:   "80F24000024F00",
			wrappedCommand: "84F24000181819D47B42BBE6B9449BBC2BD43A090DAC1F2F0A52D9F34B",
			response: "BB82442BB5CC8C839620615D1F163D3DDBC9357D68EF4BAD997CFBB79A24C224A89488C44B25C3B23D4" +
				"89E4E58A309D438FDD6E453D0E07216541FB142B977A3A7D4C4048BBE2BA068F04A0A4A9C50BAD232F8" +
				"CA8EA1F40E9000",
			plainResponseStatus: "0AA9A8A7A6A5A4A3A2A1A00F800AA0A1A2A3A4A5A6A7A8A9070009A00000015141434C00070010A000" +
				"0002202003010301000000000011070007A000000248040007009000",
		},
		{
			plainCommand:        "80F28000024F00",
			wrappedCommand:      "84F280001809F07C3DF47956B1052951FA28211BA7BABC05C321D9B3BF",
			response:            "31EB08363026463BAD10AF29F24301F1D9B8532067F9313D97FDA39BBE6B6099BEFD623E1F79FB5D9000",
			plainResponseStatus: "08A0000001510000000F9E9000",
		},
	}

	for _, step := range steps {
		command, err := apdu.ParseCommand(hexutils.MustHexToBytes(step.plainCommand))
		require.NoError(t, err)

		assert.Equal(t, step.wrappedCommand, wrapHex(t, w, command))

		response, err := apdu.ParseResponse(hexutils.MustHexToBytes(step.response))
		require.NoError(t, err)

		unwrapped, err := w.Unwrap(response)
		require.NoError(t, err)

		rawResponse, err := serializeResponse(unwrapped)
		require.NoError(t, err)
		assert.Equal(t, step.plainResponseStatus, hexutils.BytesToHex(rawResponse))
	}
}

func serializeResponse(r *apdu.Response) ([]byte, error) {
	raw := make([]byte, 0, len(r.Data)+2)
	raw = append(raw, r.Data...)
	raw = append(raw, r.Sw1, r.Sw2)

	return raw, nil
}

// Vectors of the host side reference implementation
// Ambimat-Electronics/ambisecure-gp-secure-channel (Apache-2.0), computed with the same
// static keys and challenges as the Samsung transcript above.
func TestSCP03Wrapper_Levels(t *testing.T) {
	tests := []struct {
		level        SecurityLevel
		authenticate string
		commands     [][2]string
	}{
		{
			level:        LevelCMAC,
			authenticate: "8482010010B08D6CE26B6CB3CC7E6E7B642A9F169F",
			commands: [][2]string{
				{"00A4040007A000000804000100", "04A404000FA0000008040001D3D6E0A122DC59F700"},
				{"80F28000024F0000", "84F280000A4F005B2D5B9E89E8293300"},
				{"80E602000C07A00000080400010000000000", "84E602001407A000000804000100000000CCC0A83B149895C100"},
				{"80E40080094F07A0000008040001", "84E40080114F07A0000008040001EDC75FCC46C14EDD"},
				{"80E8000004AABBCCDD", "84E800000CAABBCCDD94FA59E7455D6178"},
			},
		},
		{
			level:        LevelCDECMAC,
			authenticate: "8482030010B08D6CE26B6CB3CC36BC88E1E4ED8136",
			commands: [][2]string{
				{"00A4040007A000000804000100", "04A40400181A2964AD1347F63FDC42A96EEAE08B782838CB8AB26C158D00"},
				{"80F28000024F0000", "84F28000181819D47B42BBE6B9449BBC2BD43A090D3C570A4E8AFB60A400"},
				{"80E602000C07A00000080400010000000000", "84E60200182C5C5FD71504E5994EABB2A60F9B4AAB6CD66E37C06D8E5C00"},
				{"80E40080094F07A0000008040001", "84E4008018B6C769E840A0923A297C36D9D3103516FB81CF6E1E3FF982"},
				{"80E8000004AABBCCDD", "84E8000018EFCAB8E292B55D02F22CA52DFDC3E1F020FD5F628EADA99E"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.authenticate, func(t *testing.T) {
			session := samsungSession(t, test.level)

			w, err := session.newWrapper()
			require.NoError(t, err)

			authenticate, err := w.WrapAuthenticate(session.ExternalAuthenticate())
			require.NoError(t, err)

			raw, err := authenticate.Serialize()
			require.NoError(t, err)
			assert.Equal(t, test.authenticate, hexutils.BytesToHex(raw))

			for _, command := range test.commands {
				parsed, err := apdu.ParseCommand(hexutils.MustHexToBytes(command[0]))
				require.NoError(t, err)

				assert.Equal(t, command[1], wrapHex(t, w, parsed))
			}
		})
	}
}

// A command with no data is not encrypted, but it still consumes an encryption counter,
// so the commands that follow must not repeat an ICV (Amendment D section 6.2.6).
func TestSCP03Wrapper_CommandWithoutDataAdvancesCounter(t *testing.T) {
	session := samsungSession(t, LevelCDECMAC)

	w, err := session.newWrapper()
	require.NoError(t, err)

	_, err = w.WrapAuthenticate(session.ExternalAuthenticate())
	require.NoError(t, err)

	getStatus := apdu.NewCommand(0x80, 0xF2, 0x80, 0x00, nil)
	getStatus.SetLe(0)
	assert.Equal(t, "84F2800008553F2639B21F19A400", wrapHex(t, w, getStatus))

	load, err := apdu.ParseCommand(hexutils.MustHexToBytes("80E8000004AABBCCDD"))
	require.NoError(t, err)
	assert.Equal(t, "84E8000018144060ED9C25213194D2B0808AB1DE04B75AC5C4ED209915", wrapHex(t, w, load))

	deleteCommand, err := apdu.ParseCommand(hexutils.MustHexToBytes("80E40080094F07A0000008040001"))
	require.NoError(t, err)
	assert.Equal(t, "84E400801860AADD1EE3E1C5BE7E211E7942223695C014F298CB979560", wrapHex(t, w, deleteCommand))
}

func TestSCP03Wrapper_MaxDataSize(t *testing.T) {
	tests := []struct {
		level    SecurityLevel
		macLen   int
		expected int
	}{
		{LevelCMAC, 8, 247},
		{LevelCMAC, 16, 239},
		{LevelCDECMAC, 8, 239},
		{LevelCDECMAC, 16, 223},
		{LevelFull, 8, 239},
	}

	for _, test := range tests {
		w, err := NewSCP03Wrapper(make([]byte, 16), make([]byte, 16), make([]byte, 16), test.level, test.macLen)
		require.NoError(t, err)

		assert.Equal(t, test.expected, w.maxDataSize(), "level 0x%02x mac %d", test.level, test.macLen)
	}
}

func TestSCP03Wrapper_BadRMAC(t *testing.T) {
	session := samsungSession(t, LevelFull)

	w, err := session.newWrapper()
	require.NoError(t, err)

	_, err = w.WrapAuthenticate(session.ExternalAuthenticate())
	require.NoError(t, err)

	command, err := apdu.ParseCommand(hexutils.MustHexToBytes("80F28000024F00"))
	require.NoError(t, err)
	wrapHex(t, w, command)

	response, err := apdu.ParseResponse(hexutils.MustHexToBytes("31EB08363026463BAD10AF29F24301F1D9B8532067F9313D97FDA39BBE6B6099BEFD623E1F79FB5D9000"))
	require.NoError(t, err)

	_, err = w.Unwrap(response)
	assert.ErrorIs(t, err, ErrBadRMAC)
}

// A response with an error status word carries neither data nor R-MAC.
func TestSCP03Wrapper_ErrorResponseIsNotProtected(t *testing.T) {
	session := samsungSession(t, LevelFull)

	w, err := session.newWrapper()
	require.NoError(t, err)

	response, err := apdu.ParseResponse(hexutils.MustHexToBytes("6A82"))
	require.NoError(t, err)

	unwrapped, err := w.Unwrap(response)
	require.NoError(t, err)
	assert.Equal(t, response, unwrapped)
}

func TestSCP03Wrapper_WrappedCommandTooLong(t *testing.T) {
	session := samsungSession(t, LevelCMAC)

	w, err := session.newWrapper()
	require.NoError(t, err)

	cmd := apdu.NewCommand(0x80, 0xE8, 0x00, 0x00, make([]byte, 248))
	_, err = w.Wrap(cmd)
	assert.Error(t, err)
}

func TestNewSCP03Wrapper_BadParameters(t *testing.T) {
	key := make([]byte, 16)

	_, err := NewSCP03Wrapper(nil, key, key, LevelCMAC, 8)
	assert.Error(t, err)

	_, err = NewSCP03Wrapper(key, key, nil, LevelCMACRMAC, 8)
	assert.Error(t, err)

	_, err = NewSCP03Wrapper(key, key, key, LevelCMAC, 12)
	assert.Error(t, err)
}
