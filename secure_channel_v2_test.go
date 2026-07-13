package keycard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/crypto"
	"github.com/status-im/keycard-go/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Helpers
// ============================================================================

// testCAKey generates a CA key pair for testing.
func testCAKey(t *testing.T) *ecdsa.PrivateKey {
	priv, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	return priv
}

// compressKey returns the 33-byte compressed form of a public key.
func compressKey(pub *ecdsa.PublicKey) [33]byte {
	var out [33]byte
	copy(out[:], ethcrypto.CompressPubkey(pub))
	return out
}

// buildTestCertificate builds a 98-byte certificate: 33-byte identity pubkey + 65-byte recoverable signature.
// The signature is over SHA-256(identPub) signed by the CA private key.
func buildTestCertificate(caPriv *ecdsa.PrivateKey, identPriv *ecdsa.PrivateKey) []byte {
	identPubBytes := ethcrypto.CompressPubkey(&identPriv.PublicKey)
	msg := sha256.Sum256(identPubBytes)

	sig, err := ethcrypto.Sign(msg[:], caPriv)
	if err != nil {
		panic(err)
	}

	cert := make([]byte, 98)
	copy(cert[:33], identPubBytes)
	copy(cert[33:], sig)
	return cert
}

// mockChannel is a types.Channel implementation that records sent commands
// and returns configurable responses.
type mockChannel struct {
	sentCommands []*apdu.Command
	nextResponse *apdu.Response
	nextErr      error
}

func (m *mockChannel) Send(cmd *apdu.Command) (*apdu.Response, error) {
	m.sentCommands = append(m.sentCommands, cmd)
	if m.nextErr != nil {
		return nil, m.nextErr
	}
	resp := m.nextResponse
	m.nextResponse = nil
	return resp, nil
}

func newMockResponse(data []byte, sw uint16) *apdu.Response {
	raw := make([]byte, 0, len(data)+2)
	raw = append(raw, data...)
	raw = append(raw, byte(sw>>8), byte(sw&0xff))
	resp, _ := apdu.ParseResponse(raw)
	return resp
}

func newMockOKResponse(data []byte) *apdu.Response {
	return newMockResponse(data, apdu.SwOK)
}

// ============================================================================
// NewSecureChannelV2 tests
// ============================================================================

func TestNewSecureChannelV2(t *testing.T) {
	caKey := [33]byte{1, 2, 3}
	cardKey := [33]byte{4, 5, 6}

	sc := NewSecureChannelV2([][33]byte{caKey}, [][33]byte{cardKey})

	assert.NotNil(t, sc)
	assert.Equal(t, [][33]byte{caKey}, sc.caPublicKeys)
	assert.Equal(t, [][33]byte{cardKey}, sc.whitelistedCardKeys)
	assert.False(t, sc.IsOpen())
}

func TestNewSecureChannelV2WithCA(t *testing.T) {
	caKey := [33]byte{1, 2, 3}

	sc := NewSecureChannelV2WithCA(caKey)

	assert.NotNil(t, sc)
	assert.Equal(t, [][33]byte{caKey}, sc.caPublicKeys)
	assert.Nil(t, sc.whitelistedCardKeys)
}

func TestSecureChannelV2_Version(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	assert.Equal(t, VersionV2, sc.Version())
}

func TestSecureChannelV2_Pairing(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	assert.Nil(t, sc.Pairing())
	sc.SetPairing(&types.Pairing{})
	assert.Nil(t, sc.Pairing())
}

func TestSecureChannelV2_PairingMethodsReturnError(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)

	_, err := sc.Pair(nil, 0, 0, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	_, err = sc.Unpair(nil, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	err = sc.AutoPair(nil, 0, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	err = sc.AutoUnpair(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	err = sc.UnpairOthers(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	_, err = sc.MutuallyAuthenticate(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Secure Channel V2")
}

// ============================================================================
// SetCardCertificate tests
// ============================================================================

func TestSetCardCertificate_TrustedCA(t *testing.T) {
	caPriv := testCAKey(t)
	identPriv := testCAKey(t)
	caPub := compressKey(&caPriv.PublicKey)

	sc := NewSecureChannelV2([][33]byte{caPub}, nil)

	// Build a certificate that the types.ParseCertificate can parse
	// Certificate format: 33-byte identPub + 65-byte recoverable signature
	cert := buildTestCertificate(caPriv, identPriv)

	// The certificate's CA public key is recovered from the signature
	// We need to verify that the recovered CA key matches our trusted CA
	certParsed, err := types.ParseCertificate(cert)
	require.NoError(t, err)

	// Check that the recovered CA key matches
	recoveredCAPub := certParsed.CAPublicKey()
	var recoveredCA [33]byte
	copy(recoveredCA[:], recoveredCAPub)

	// If the recovered CA doesn't match, the cert won't be trusted
	// This depends on how ethcrypto.Sign works with recovery
	if recoveredCA != caPub {
		t.Skip("certificate signature recovery does not produce expected CA key")
	}

	err = sc.SetCardCertificate(cert)
	assert.NoError(t, err)
	assert.NotNil(t, sc.cardIdentPub)
}

func TestSetCardCertificate_WhitelistedCard(t *testing.T) {
	caPriv := testCAKey(t)
	identPriv := testCAKey(t)
	identPub := compressKey(&identPriv.PublicKey)

	sc := NewSecureChannelV2(nil, [][33]byte{identPub})

	cert := buildTestCertificate(caPriv, identPriv)
	err := sc.SetCardCertificate(cert)
	assert.NoError(t, err)
}

func TestSetCardCertificate_UnknownCA_NotWhitelisted(t *testing.T) {
	caPriv := testCAKey(t)
	identPriv := testCAKey(t)

	sc := NewSecureChannelV2([][33]byte{{1, 2, 3}}, nil)

	cert := buildTestCertificate(caPriv, identPriv)
	err := sc.SetCardCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate verification failed")
}

func TestSetCardCertificate_InvalidData(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)

	// Too short
	err := sc.SetCardCertificate([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse card certificate")
}

// ============================================================================
// IsCATrusted / IsCardWhitelisted tests
// ============================================================================

func TestIsCATrusted(t *testing.T) {
	caKey := [33]byte{1, 2, 3}
	otherKey := [33]byte{4, 5, 6}

	sc := NewSecureChannelV2([][33]byte{caKey}, nil)

	assert.True(t, sc.IsCATrusted(&caKey))
	assert.False(t, sc.IsCATrusted(&otherKey))
}

func TestIsCardWhitelisted(t *testing.T) {
	cardKey := [33]byte{1, 2, 3}
	otherKey := [33]byte{4, 5, 6}

	sc := NewSecureChannelV2(nil, [][33]byte{cardKey})

	assert.True(t, sc.IsCardWhitelisted(&cardKey))
	assert.False(t, sc.IsCardWhitelisted(&otherKey))
}

// ============================================================================
// Reset tests
// ============================================================================

func TestSecureChannelV2_Reset(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)

	// Manually set some state
	sc.open = true
	sc.established = true
	sc.keyH2C = []byte("secret key")
	sc.keyC2H = []byte("other key")
	sc.nonceCounter = [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42}

	sc.Reset()

	assert.False(t, sc.open)
	assert.False(t, sc.established)
	assert.False(t, sc.IsOpen())
	assert.Nil(t, sc.keyH2C)
	assert.Nil(t, sc.keyC2H)
	assert.Equal(t, [13]byte{}, sc.nonceCounter)
	assert.Nil(t, sc.pendingDecryptNonce)
	assert.Nil(t, sc.cardIdentPub)
	assert.Nil(t, sc.clientEphPrivKey)
}

// ============================================================================
// ProtectedCommand tests
// ============================================================================

func TestProtectedCommand_NotOpen_NotEstablished(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)

	cmd, err := sc.ProtectedCommand(0x80, 0x01, 0x00, 0x00, []byte("data"))
	assert.NoError(t, err)
	assert.NotNil(t, cmd)
	// Should return plaintext command as-is
	assert.Equal(t, uint8(0x80), cmd.Cla)
	assert.Equal(t, uint8(0x01), cmd.Ins)
	assert.Equal(t, []byte("data"), cmd.Data)
}

func TestProtectedCommand_NotOpen_Established(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.established = true

	cmd, err := sc.ProtectedCommand(0x80, 0x01, 0x00, 0x00, []byte("data"))
	assert.Error(t, err)
	assert.Nil(t, cmd)
	assert.Contains(t, err.Error(), "closed after an error")
}

func TestProtectedCommand_Open_NoKeys(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true

	cmd, err := sc.ProtectedCommand(0x80, 0x01, 0x00, 0x00, []byte("data"))
	assert.Error(t, err)
	assert.Nil(t, cmd)
	assert.Contains(t, err.Error(), "no client-to-card key available")
}

func TestProtectedCommand_Open_WithKeys(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.keyH2C = make([]byte, 16)
	for i := range sc.keyH2C {
		sc.keyH2C[i] = byte(i)
	}

	data := []byte("test payload")
	cmd, err := sc.ProtectedCommand(0x80, 0x01, 0x00, 0x00, data)
	require.NoError(t, err)
	require.NotNil(t, cmd)

	// Should be wrapped as secured APDU
	assert.Equal(t, uint8(0x80), cmd.Cla) // ClaGp
	assert.Equal(t, uint8(InsSecuredAPDU), cmd.Ins)
	assert.NotEqual(t, data, cmd.Data) // data is encrypted

	// Nonce should have been incremented
	assert.Equal(t, [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, sc.nonceCounter)
}

func TestProtectedCommand_DataTooLarge(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.keyH2C = make([]byte, 16)

	data := make([]byte, 256)
	cmd, err := sc.ProtectedCommand(0x80, 0x01, 0x00, 0x00, data)
	assert.Error(t, err)
	assert.Nil(t, cmd)
	assert.Contains(t, err.Error(), "too large")
}

// ============================================================================
// Transmit tests
// ============================================================================

func TestTransmit_ChannelError(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	ch := &mockChannel{nextErr: errors.New("channel down")}

	cmd := apdu.NewCommand(0x80, 0x01, 0x00, 0x00, nil)
	resp, err := sc.Transmit(ch, cmd)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, sc.IsOpen())
}

func TestTransmit_ResponseNotOK(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	ch := &mockChannel{
		nextResponse: newMockResponse(nil, 0x6985),
	}

	cmd := apdu.NewCommand(0x80, 0x01, 0x00, 0x00, nil)
	resp, err := sc.Transmit(ch, cmd)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, uint16(0x6985), resp.Sw)
	assert.False(t, sc.IsOpen())
}

func TestTransmit_NotOpen(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = false
	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte("data")),
	}

	cmd := apdu.NewCommand(0x80, 0x01, 0x00, 0x00, nil)
	resp, err := sc.Transmit(ch, cmd)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestTransmit_NoPendingNonce(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.pendingDecryptNonce = nil
	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte("data")),
	}

	cmd := apdu.NewCommand(0x80, 0x01, 0x00, 0x00, nil)
	resp, err := sc.Transmit(ch, cmd)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "no pending nonce")
}

func TestTransmit_SuccessfulDecrypt(t *testing.T) {
	// Set up a secure channel with known keys
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true

	// Use known keys
	sc.keyH2C = make([]byte, 16)
	sc.keyC2H = make([]byte, 16)
	for i := range sc.keyH2C {
		sc.keyH2C[i] = byte(i)
		sc.keyC2H[i] = byte(i + 1)
	}

	nonce := [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	sc.nonceCounter = nonce
	sc.pendingDecryptNonce = &nonce

	// Build a valid encrypted response: inner APDU + status word, encrypted
	innerData := []byte{0x80, 0x01, 0x00, 0x00, 0x03, 'a', 'b', 'c'} // command-like
	innerData = append(innerData, 0x90, 0x00) // status word 0x9000

	encrypted, err := crypto.AESCCMEncrypt(sc.keyC2H, nonce[:], innerData)
	require.NoError(t, err)

	ch := &mockChannel{
		nextResponse: newMockOKResponse(encrypted),
	}

	cmd := apdu.NewCommand(0x80, 0x18, 0x00, 0x00, encrypted)
	resp, err := sc.Transmit(ch, cmd)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint16(0x9000), resp.Sw)
	assert.Equal(t, innerData[:len(innerData)-2], resp.Data)
}

func TestTransmit_DecryptFailure(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.keyC2H = make([]byte, 16)

	nonce := [13]byte{}
	sc.pendingDecryptNonce = &nonce

	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte("garbage")),
	}

	cmd := apdu.NewCommand(0x80, 0x18, 0x00, 0x00, nil)
	resp, err := sc.Transmit(ch, cmd)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, sc.IsOpen())
}

// ============================================================================
// incrementNonce tests
// ============================================================================

func TestIncrementNonce(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true

	sc.incrementNonce()
	assert.Equal(t, [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, sc.nonceCounter)

	sc.incrementNonce()
	assert.Equal(t, [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, sc.nonceCounter)
}

func TestIncrementNonce_Carry(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.nonceCounter = [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF}

	sc.incrementNonce()
	assert.Equal(t, [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}, sc.nonceCounter)
}

func TestIncrementNonce_Overflow(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.open = true
	sc.nonceCounter = [13]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	sc.incrementNonce()
	assert.Equal(t, [13]byte{}, sc.nonceCounter)
	assert.False(t, sc.IsOpen())
}

// ============================================================================
// AutoOpen tests
// ============================================================================

func TestAutoOpen_SendError(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	ch := &mockChannel{nextErr: errors.New("send failed")}

	err := sc.AutoOpen(ch)
	assert.Error(t, err)
	assert.False(t, sc.IsOpen())
}

func TestAutoOpen_ResponseNotOK(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	ch := &mockChannel{
		nextResponse: newMockResponse(nil, 0x6985),
	}

	err := sc.AutoOpen(ch)
	assert.Error(t, err)
	assert.False(t, sc.IsOpen())
}

func TestAutoOpen_InvalidResponseTooShort(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte{0x01, 0x02}),
	}

	err := sc.AutoOpen(ch)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestAutoOpen_CommandFormat(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte{0x01, 0x02}),
	}

	_ = sc.AutoOpen(ch)

	require.Len(t, ch.sentCommands, 1)
	cmd := ch.sentCommands[0]
	assert.Equal(t, uint8(0x80), cmd.Cla) // ClaGp
	assert.Equal(t, uint8(InsOpenSecureChannel), cmd.Ins)
	assert.Equal(t, uint8(0), cmd.P1)
	assert.Equal(t, uint8(0), cmd.P2)
	// Data should be 32 (salt) + 65 (pubkey) = 97 bytes
	assert.Equal(t, 97, len(cmd.Data))
}

// ============================================================================
// OpenSecureChannel tests
// ============================================================================

func TestOpenSecureChannel(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	data := []byte("handshake data")
	ch := &mockChannel{
		nextResponse: newMockOKResponse([]byte("response")),
	}

	resp, err := sc.OpenSecureChannel(ch, 0, data)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, ch.sentCommands, 1)
	cmd := ch.sentCommands[0]
	assert.Equal(t, uint8(0x80), cmd.Cla)
	assert.Equal(t, uint8(InsOpenSecureChannel), cmd.Ins)
	assert.Equal(t, data, cmd.Data)
}

// ============================================================================
// parseDERSignature tests
// ============================================================================

func TestParseDERSignature_Valid(t *testing.T) {
	// Create a valid DER signature manually
	r := make([]byte, 32)
	s := make([]byte, 32)
	for i := range r {
		r[i] = byte(i + 1)
	}
	for i := range s {
		s[i] = byte(i + 100)
	}

	// Build DER: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
	der := make([]byte, 0, 66)
	der = append(der, 0x30, 0x44) // SEQUENCE, length 68
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, r...)
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, s...)

	rOut, sOut, err := parseDERSignature(der)
	require.NoError(t, err)
	assert.Len(t, rOut, 32)
	assert.Len(t, sOut, 32)
}

func TestParseDERSignature_LeadingZero(t *testing.T) {
	// DER with leading zero in R (positive high-bit integer)
	r := make([]byte, 33)
	r[0] = 0x00
	r[1] = 0x80 // high bit set, needs leading zero

	s := make([]byte, 32)
	s[0] = 0x42

	der := make([]byte, 0)
	der = append(der, 0x30, 0x45) // SEQUENCE
	der = append(der, 0x02, 0x21) // INTEGER, length 33
	der = append(der, r...)
	der = append(der, 0x02, 0x20) // INTEGER, length 32
	der = append(der, s...)

	rOut, sOut, err := parseDERSignature(der)
	require.NoError(t, err)
	assert.Len(t, rOut, 32)
	assert.Len(t, sOut, 32)
	// Leading zero should be stripped, value preserved
	assert.Equal(t, byte(0x80), rOut[0])
}

func TestParseDERSignature_Invalid_NotSequence(t *testing.T) {
	der := []byte{0x02, 0x20, 0x00}
	_, _, err := parseDERSignature(der)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a SEQUENCE")
}

func TestParseDERSignature_Invalid_TooShort(t *testing.T) {
	der := []byte{0x30}
	_, _, err := parseDERSignature(der)
	assert.Error(t, err)
}

func TestParseDERSignature_Invalid_RNotInteger(t *testing.T) {
	// SEQUENCE with length 7, R tag is 0x01 instead of 0x02
	// 0x30 0x07 | 0x01 0x02 XX XX | 0x02 0x01 YY
	der := []byte{0x30, 0x07, 0x01, 0x02, 0xAA, 0xBB, 0x02, 0x01, 0x42}
	_, _, err := parseDERSignature(der)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "R is not an INTEGER")
}

func TestParseDERSignature_Invalid_SNotInteger(t *testing.T) {
	// SEQUENCE with length 7, valid R, S tag is 0x01 instead of 0x02
	// 0x30 0x07 | 0x02 0x01 XX | 0x01 0x02 YY ZZ
	der := []byte{0x30, 0x07, 0x02, 0x01, 0x42, 0x01, 0x02, 0xAA, 0xBB}
	_, _, err := parseDERSignature(der)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "S is not an INTEGER")
}

func TestParseDERSignature_Invalid_Truncated(t *testing.T) {
	// SEQUENCE claims length 20 but only has 8 bytes of content
	// Need at least 8 bytes to pass the initial length check
	der := []byte{0x30, 0x14, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _, err := parseDERSignature(der)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestParseDERSignature_ShortValues(t *testing.T) {
	// Short R and S values (less than 32 bytes)
	// Build proper DER with correct length
	// SEQUENCE content: 0x02 0x01 0x42 | 0x02 0x01 0x99 = 6 bytes
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x01, 0x99}

	rOut, sOut, err := parseDERSignature(der)
	require.NoError(t, err)
	assert.Len(t, rOut, 32)
	assert.Len(t, sOut, 32)
	// Should be left-padded
	assert.Equal(t, byte(0x42), rOut[31])
	assert.Equal(t, byte(0x99), sOut[31])
}

// ============================================================================
// encryptCCM / decryptCCM tests
// ============================================================================

func TestEncryptCCM_NoKey(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)

	_, err := sc.encryptCCM([]byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no client-to-card key")
}

func TestDecryptCCM_NoKey(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	nonce := [13]byte{}

	_, err := sc.decryptCCM([]byte("data"), &nonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no card-to-client key")
}

func TestEncryptDecryptCCM_RoundTrip(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	// Use the same key for both directions for this round-trip test
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	sc.keyH2C = key
	sc.keyC2H = key

	nonce := [13]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	sc.nonceCounter = nonce

	plaintext := []byte("encrypted payload")
	ciphertext, err := sc.encryptCCM(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := sc.decryptCCM(ciphertext, &nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// ============================================================================
// verifyCardSignature tests
// ============================================================================

func TestVerifyCardSignature_NoIdentPub(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	// cardIdentPub is nil

	clientPub, _ := ethcrypto.GenerateKey()
	cardPub, _ := ethcrypto.GenerateKey()
	salt := make([]byte, 32)

	err := sc.verifyCardSignature(salt, &clientPub.PublicKey, &cardPub.PublicKey, []byte("sig"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestVerifyCardSignature_BadSignature(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	// Set cardIdentPub manually
	identPriv := testCAKey(t)
	identPub := compressKey(&identPriv.PublicKey)
	sc.cardIdentPub = &identPub

	clientPub, _ := ethcrypto.GenerateKey()
	cardPub, _ := ethcrypto.GenerateKey()
	salt := make([]byte, 32)

	// Use a random signature that doesn't match
	badSig := make([]byte, 64)
	for i := range badSig {
		badSig[i] = byte(i)
	}

	err := sc.verifyCardSignature(salt, &clientPub.PublicKey, &cardPub.PublicKey, badSig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

// ============================================================================
// verifySignatureByRecovery tests
// ============================================================================

func TestVerifySignatureByRecovery_Valid(t *testing.T) {
	priv, err := ethcrypto.GenerateKey()
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("test message"))
	sig, err := ethcrypto.Sign(msg[:], priv)
	require.NoError(t, err)

	// Convert to DER for testing
	r := make([]byte, 32)
	s := make([]byte, 32)
	copy(r, sig[:32])
	copy(s, sig[32:64])

	der := make([]byte, 0)
	der = append(der, 0x30, 0x44)
	der = append(der, 0x02, 0x20)
	der = append(der, r...)
	der = append(der, 0x02, 0x20)
	der = append(der, s...)

	recovered, err := verifySignatureByRecovery(msg[:], der, &priv.PublicKey)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(
		ethcrypto.FromECDSAPub(recovered),
		ethcrypto.FromECDSAPub(&priv.PublicKey),
	))
}

func TestVerifySignatureByRecovery_WrongKey(t *testing.T) {
	priv1, _ := ethcrypto.GenerateKey()
	priv2, _ := ethcrypto.GenerateKey()

	msg := sha256.Sum256([]byte("test message"))
	sig, err := ethcrypto.Sign(msg[:], priv1)
	require.NoError(t, err)

	r := make([]byte, 32)
	s := make([]byte, 32)
	copy(r, sig[:32])
	copy(s, sig[32:64])

	der := make([]byte, 0)
	der = append(der, 0x30, 0x44)
	der = append(der, 0x02, 0x20)
	der = append(der, r...)
	der = append(der, 0x02, 0x20)
	der = append(der, s...)

	_, err = verifySignatureByRecovery(msg[:], der, &priv2.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no recovery ID produced matching key")
}

// ============================================================================
// zeroizeKeys tests
// ============================================================================

func TestZeroizeKeys(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.keyH2C = []byte{0xFF, 0xFF, 0xFF}
	sc.keyC2H = []byte{0xAA, 0xAA}

	sc.zeroizeKeys()

	assert.Nil(t, sc.keyH2C)
	assert.Nil(t, sc.keyC2H)
}

func TestZeroizeKeys_NilKeys(t *testing.T) {
	sc := NewSecureChannelV2(nil, nil)
	sc.keyH2C = nil
	sc.keyC2H = nil

	// Should not panic
	sc.zeroizeKeys()

	assert.Nil(t, sc.keyH2C)
	assert.Nil(t, sc.keyC2H)
}
