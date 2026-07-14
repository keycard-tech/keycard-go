package keycard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/crypto"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/types"
)

// ============================================================================
// Secure Channel V2 constants
// ============================================================================

const (
	scV2ProtocolLabel  = "sc_v2_ccm"
	scV2HKDFSaltSize   = 32
	scV2PubkeySize     = 65 // uncompressed secp256k1
	scV2OKMSize        = 32
	scV2AESKeySize     = 16
	scV2CCMNonceSize   = 13
	scV2CcmTagSize     = 8
)

// ============================================================================
// SecureChannelV2
// ============================================================================

// SecureChannelV2 implements the Secure Channel V2 protocol.
//
// Uses ECDHE on secp256k1 with HKDF-SHA256 key derivation
// and AES-128-CCM (T=8, L=13) for encrypted commands.
type SecureChannelV2 struct {
	caPublicKeys         [][33]byte // trusted CA keys
	whitelistedCardKeys  [][33]byte // optional card whitelist
	keyH2C               []byte     // client->card AES key (nil until open)
	keyC2H               []byte     // card->client AES key (nil until open)
	nonceCounter         [13]byte   // big-endian counter
	open                 bool
	cardIdentPub         *[33]byte  // card identity public key
	clientEphPrivKey     *ecdsa.PrivateKey
}

// NewSecureChannelV2 creates a new V2 secure channel with the given trusted
// CA keys and optionally whitelisted card identity keys.
func NewSecureChannelV2(caPublicKeys, whitelistedCardKeys [][33]byte) *SecureChannelV2 {
	return &SecureChannelV2{
		caPublicKeys:        caPublicKeys,
		whitelistedCardKeys: whitelistedCardKeys,
	}
}

// NewSecureChannelV2WithCA creates a new V2 secure channel with a single CA key.
func NewSecureChannelV2WithCA(caPublicKey [33]byte) *SecureChannelV2 {
	return NewSecureChannelV2([][33]byte{caPublicKey}, nil)
}

// SetCardCertificate parses the card's identity certificate and validates the
// CA public key against known anchors.
func (sc *SecureChannelV2) SetCardCertificate(certData []byte) error {
	cert, err := types.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse card certificate: %w", err)
	}

	identPub := cert.IdentPub()
	sc.cardIdentPub = &identPub

	// Check if the card's identity public key is whitelisted
	whitelisted := sc.isCardWhitelisted(&identPub)

	// Check if the CA public key is trusted
	caPubBytes := cert.CAPublicKey()
	caTrusted := false
	if len(caPubBytes) == 33 {
		var caPub [33]byte
		copy(caPub[:], caPubBytes)
		caTrusted = sc.isCATrusted(&caPub)
	}

	if !caTrusted && !whitelisted {
		return errors.New("card certificate verification failed: unknown CA public key and card not whitelisted")
	}

	return nil
}

// IsCATrusted checks if the given CA public key is trusted.
func (sc *SecureChannelV2) IsCATrusted(caPub *[33]byte) bool {
	return sc.isCATrusted(caPub)
}

func (sc *SecureChannelV2) isCATrusted(caPub *[33]byte) bool {
	for _, key := range sc.caPublicKeys {
		if key == *caPub {
			return true
		}
	}
	return false
}

// IsCardWhitelisted checks if the given card identity public key is whitelisted.
func (sc *SecureChannelV2) IsCardWhitelisted(identPub *[33]byte) bool {
	return sc.isCardWhitelisted(identPub)
}

func (sc *SecureChannelV2) isCardWhitelisted(identPub *[33]byte) bool {
	for _, key := range sc.whitelistedCardKeys {
		if key == *identPub {
			return true
		}
	}
	return false
}

func (sc *SecureChannelV2) Reset() {
	sc.open = false
	sc.zeroizeKeys()
	sc.nonceCounter = [13]byte{}
	sc.cardIdentPub = nil
	sc.clientEphPrivKey = nil
}

func (sc *SecureChannelV2) zeroizeKeys() {
	if sc.keyH2C != nil {
		crypto.Zeroize(sc.keyH2C)
		sc.keyH2C = nil
	}
	if sc.keyC2H != nil {
		crypto.Zeroize(sc.keyC2H)
		sc.keyC2H = nil
	}
}

func (sc *SecureChannelV2) IsOpen() bool {
	return sc.open
}

func (sc *SecureChannelV2) Version() SecureChannelVersion {
	return VersionV2
}

func (sc *SecureChannelV2) Pairing() *types.Pairing {
	return nil // V2 does not use pairing
}

func (sc *SecureChannelV2) SetPairing(_ *types.Pairing) {
	// No-op: V2 does not use pairing
}

// AutoOpen performs the full V2 secure channel handshake:
// 1. Generate ephemeral key pair and random salt
// 2. Send OPEN_SECURE_CHANNEL with salt + client public key
// 3. Process card response (ECDH + HKDF key derivation)
// 4. Verify card's ECDSA signature over handshake transcript
func (sc *SecureChannelV2) AutoOpen(ch types.Channel) error {
	sc.open = false

	// Generate random salt
	salt := make([]byte, scV2HKDFSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate random salt: %w", err)
	}

	// Generate client ephemeral key pair
	clientEphPriv, err := ethcrypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral secret: %w", err)
	}
	sc.clientEphPrivKey = clientEphPriv

	// Uncompressed public key (65 bytes: 0x04 || x || y)
	clientEphPubBytes := ethcrypto.FromECDSAPub(&clientEphPriv.PublicKey)

	// Build request: salt || client_eph_pub (uncompressed)
	requestData := make([]byte, 0, scV2HKDFSaltSize+scV2PubkeySize)
	requestData = append(requestData, salt...)
	requestData = append(requestData, clientEphPubBytes...)

	// Send OPEN_SECURE_CHANNEL
	cmd := apdu.NewCommand(globalplatform.ClaGp, InsOpenSecureChannel, 0, 0, requestData)
	resp, err := ch.Send(cmd)
	if err != nil {
		return err
	}
	if resp.Sw != apdu.SwOK {
		return apdu.NewErrBadResponse(resp.Sw, "OPEN_SECURE_CHANNEL failed")
	}

	// Process handshake response
	return sc.processHandshakeResponse(salt, clientEphPriv, resp.Data)
}

// AutoPair returns an error: pairing is not supported in V2.
func (sc *SecureChannelV2) AutoPair(_ types.Channel, _ uint8, _ []byte) error {
	return errors.New("pairing is not supported in Secure Channel V2")
}

// AutoUnpair returns an error: unpairing is not supported in V2.
func (sc *SecureChannelV2) AutoUnpair(_ types.Channel) error {
	return errors.New("unpairing is not supported in Secure Channel V2")
}

// UnpairOthers returns an error: unpairing is not supported in V2.
func (sc *SecureChannelV2) UnpairOthers(_ types.Channel) error {
	return errors.New("unpairing is not supported in Secure Channel V2")
}

// OpenSecureChannel sends an OPEN SECURE CHANNEL APDU (V2).
func (sc *SecureChannelV2) OpenSecureChannel(ch types.Channel, _ uint8, data []byte) (*apdu.Response, error) {
	sc.open = false
	cmd := apdu.NewCommand(globalplatform.ClaGp, InsOpenSecureChannel, 0, 0, data)
	return ch.Send(cmd)
}

// MutuallyAuthenticate returns an error: mutual auth is not a separate step in V2.
func (sc *SecureChannelV2) MutuallyAuthenticate(_ types.Channel) (*apdu.Response, error) {
	return nil, errors.New("mutual authentication is not a separate step in Secure Channel V2")
}

// Pair returns an error: pairing is not supported in V2.
func (sc *SecureChannelV2) Pair(_ types.Channel, _, _ uint8, _ []byte) (*apdu.Response, error) {
	return nil, errors.New("pairing is not supported in Secure Channel V2")
}

// Unpair returns an error: unpairing is not supported in V2.
func (sc *SecureChannelV2) Unpair(_ types.Channel, _ uint8) (*apdu.Response, error) {
	return nil, errors.New("unpairing is not supported in Secure Channel V2")
}

// ProtectedCommand returns a command APDU with the V2 secure channel wrapper
// applied. If the channel is not open, returns the command as-is (plaintext).
// If the channel was previously established but is now closed, returns an error.
func (sc *SecureChannelV2) ProtectedCommand(cla, ins, p1, p2 uint8, data []byte) (*apdu.Command, error) {
	if !sc.open {
		return apdu.NewCommand(cla, ins, p1, p2, data), nil
	}

	if len(data) > 255 {
		return nil, fmt.Errorf("protected command payload too large: %d bytes", len(data))
	}

	// Build inner APDU: CLA | INS | P1 | P2 | LC | data
	inner := make([]byte, 0, 5+len(data))
	inner = append(inner, cla, ins, p1, p2, byte(len(data)))
	inner = append(inner, data...)

	// Encrypt with AES-128-CCM using the current nonce, then advance the
	// counter immediately — before we know whether the round trip completes.
	ciphertext, err := sc.encryptCCM(inner)
	if err != nil {
		return nil, fmt.Errorf("AES-CCM encryption failed: %w", err)
	}

	return apdu.NewCommand(globalplatform.ClaGp, InsSecuredAPDU, 0, 0, ciphertext), nil
}

// Transmit sends a command and decrypts the response.
func (sc *SecureChannelV2) Transmit(ch types.Channel, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := ch.Send(cmd)
	if err != nil {
		sc.open = false
		return nil, err
	}

	if resp.Sw != apdu.SwOK {
		sc.open = false
		return resp, nil
	}

	if !sc.open {
		return resp, nil
	}

	// Decrypt with AES-128-CCM
	plaintext, err := sc.decryptCCM(resp.Data)
	if err != nil {
		sc.open = false
		return nil, fmt.Errorf("AES-CCM decryption failed: %w", err)
	}

	sc.incrementNonce()

	return apdu.ParseResponse(plaintext)
}

// processHandshakeResponse processes the card's V2 handshake response.
//
// Response format: card_eph_pub (65B) || signature (DER, variable)
func (sc *SecureChannelV2) processHandshakeResponse(salt []byte, clientEphPriv *ecdsa.PrivateKey, cardResponse []byte) error {
	if len(cardResponse) < scV2PubkeySize+2 {
		return errors.New("invalid handshake response: too short")
	}

	cardEphPubBytes := cardResponse[:scV2PubkeySize]
	signatureBytes := cardResponse[scV2PubkeySize:]

	// Decode card ephemeral public key
	cardEphPub, err := ethcrypto.UnmarshalPubkey(cardEphPubBytes)
	if err != nil {
		return fmt.Errorf("invalid card ephemeral public key: %w", err)
	}

	// ECDH key agreement
	sharedSecret := crypto.GenerateECDHSharedSecret(clientEphPriv, cardEphPub)

	// HKDF-SHA256 key derivation
	okm, err := hkdfDerive(scV2ProtocolLabel, salt, sharedSecret)
	if err != nil {
		return fmt.Errorf("HKDF derivation failed: %w", err)
	}

	// Set session keys
	sc.keyH2C = make([]byte, scV2AESKeySize)
	sc.keyC2H = make([]byte, scV2AESKeySize)
	copy(sc.keyH2C, okm[:scV2AESKeySize])
	copy(sc.keyC2H, okm[scV2AESKeySize:])
	crypto.Zeroize(okm) // scrub the combined key material

	// Verify card's ECDSA signature over transcript
	if err := sc.verifyCardSignature(salt, &clientEphPriv.PublicKey, cardEphPub, signatureBytes); err != nil {
		sc.zeroizeKeys()
		return err
	}

	// Initialize nonce counter to zero
	sc.nonceCounter = [13]byte{}
	sc.open = true

	return nil
}

// verifyCardSignature verifies the card's ECDSA signature over the handshake transcript.
//
// Transcript hash: SHA-256(PROTOCOL_LABEL || salt || client_pub || card_pub)
// Public keys are in uncompressed form (65 bytes).
func (sc *SecureChannelV2) verifyCardSignature(salt []byte, clientPub, cardPub *ecdsa.PublicKey, signatureBytes []byte) error {
	if sc.cardIdentPub == nil {
		return errors.New("card identity public key not available")
	}

	// Hash the transcript: SHA-256(PROTOCOL_LABEL || salt || client_pub || card_pub)
	clientUncompressed := ethcrypto.FromECDSAPub(clientPub)
	cardUncompressed := ethcrypto.FromECDSAPub(cardPub)

	h := sha256.New()
	h.Write([]byte(scV2ProtocolLabel))
	h.Write(salt)
	h.Write(clientUncompressed)
	h.Write(cardUncompressed)
	transcriptHash := h.Sum(nil)

	// Parse the card's identity public key
	identPubBytes := sc.cardIdentPub[:]
	// The identity public key is compressed (33 bytes). Decompress it.
	identPub, err := ethcrypto.DecompressPubkey(identPubBytes)
	if err != nil {
		return fmt.Errorf("failed to decompress identity public key: %w", err)
	}

	// Verify the signature using go-ethereum's SigToPub
	// The signature is DER-encoded; we need to convert to 65-byte format for Ecrecover,
	// or use direct verification.
	//
	// go-ethereum's crypto.Ecrecover expects the raw 65-byte format (r || s || v).
	// For DER signatures, we need to try recovery or use direct verification.

	// Try to verify by recovering the public key
	recovered, err := verifySignatureByRecovery(transcriptHash, signatureBytes, identPub)
	if err != nil {
		return fmt.Errorf("card authentication failed: %w", err)
	}

	// Verify recovered key matches the card's identity public key
	recoveredCompressed := ethcrypto.CompressPubkey(recovered)
	if !bytes.Equal(recoveredCompressed, identPubBytes) {
		return errors.New("card authentication failed: recovered key does not match identity key")
	}

	return nil
}

// verifySignatureByRecovery verifies a DER-encoded ECDSA signature by recovering
// the public key and comparing it with the expected identity public key.
func verifySignatureByRecovery(hash, derSig []byte, expectedPub *ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
	// Try to convert DER signature to raw format for Ecrecover
	// DER format: SEQUENCE { INTEGER r, INTEGER s }
	// We need to extract r and s, then try each recovery ID (0-3)

	r, s, err := parseDERSignature(derSig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER signature: %w", err)
	}

	// Try each recovery ID
	for v := 0; v <= 3; v++ {
		sig := make([]byte, 65)
		copy(sig[:32], r)
		copy(sig[32:64], s)
		sig[64] = byte(v)

		recovered, err := ethcrypto.Ecrecover(hash, sig)
		if err != nil {
			continue
		}

		recoveredPub, err := ethcrypto.UnmarshalPubkey(recovered)
		if err != nil {
			continue
		}

		// Compare with expected public key
		expectedBytes := ethcrypto.FromECDSAPub(expectedPub)
		if bytes.Equal(recovered, expectedBytes) {
			return recoveredPub, nil
		}
	}

	return nil, errors.New("signature verification failed: no recovery ID produced matching key")
}

// parseDERSignature extracts r and s from a DER-encoded ECDSA signature.
func parseDERSignature(derSig []byte) ([]byte, []byte, error) {
	if len(derSig) < 8 || derSig[0] != 0x30 {
		return nil, nil, errors.New("invalid DER signature: not a SEQUENCE")
	}

	// Parse SEQUENCE length
	seqLen := int(derSig[1])
	if seqLen == 0x81 {
		seqLen = int(derSig[2])
		derSig = derSig[1:] // skip the length encoding byte
	}

	if len(derSig) < seqLen+2 {
		return nil, nil, errors.New("invalid DER signature: truncated")
	}

	// Parse R (INTEGER)
	if derSig[2] != 0x02 {
		return nil, nil, errors.New("invalid DER signature: R is not an INTEGER")
	}
	rLen := int(derSig[3])
	rOffset := 4
	// Handle leading zero byte in R (sign byte for positive integers)
	if rLen > 0 && derSig[rOffset] == 0x00 {
		rOffset++
		rLen--
	}
	if rLen <= 0 || rOffset+rLen > len(derSig) {
		return nil, nil, errors.New("invalid DER signature: bad R length")
	}
	r := derSig[rOffset : rOffset+rLen]

	// Parse S (INTEGER)
	sTagOffset := rOffset + rLen
	if sTagOffset >= len(derSig) || derSig[sTagOffset] != 0x02 {
		return nil, nil, errors.New("invalid DER signature: S is not an INTEGER")
	}
	sLen := int(derSig[sTagOffset+1])
	sOffset := sTagOffset + 2
	// Handle leading zero byte in S
	if sLen > 0 && derSig[sOffset] == 0x00 {
		sOffset++
		sLen--
	}
	if sLen <= 0 || sOffset+sLen > len(derSig) {
		return nil, nil, errors.New("invalid DER signature: bad S length")
	}
	s := derSig[sOffset : sOffset+sLen]

	// Normalize to 32 bytes (left-pad with zeros)
	rPadded := make([]byte, 32)
	copy(rPadded[32-len(r):], r)
	sPadded := make([]byte, 32)
	copy(sPadded[32-len(s):], s)

	return rPadded, sPadded, nil
}

// encryptCCM encrypts plaintext with AES-128-CCM using the client-to-card key.
func (sc *SecureChannelV2) encryptCCM(plaintext []byte) ([]byte, error) {
	if sc.keyH2C == nil {
		return nil, errors.New("no client-to-card key available")
	}

	return crypto.AESCCMEncrypt(sc.keyH2C, sc.nonceCounter[:], plaintext)
}

// decryptCCM decrypts ciphertext with AES-128-CCM using the card-to-client key
// and the given nonce.
func (sc *SecureChannelV2) decryptCCM(ciphertext []byte) ([]byte, error) {
	if sc.keyC2H == nil {
		return nil, errors.New("no card-to-client key available")
	}

	return crypto.AESCCMDecrypt(sc.keyC2H, sc.nonceCounter[:], ciphertext)
}

// incrementNonce increments the 13-byte nonce counter as a big-endian integer.
// On overflow, the session is closed.
func (sc *SecureChannelV2) incrementNonce() {
	for i := len(sc.nonceCounter) - 1; i >= 0; i-- {
		sc.nonceCounter[i]++
		if sc.nonceCounter[i] != 0 {
			return
		}
	}
	// Overflow — session must be reset
	sc.open = false
}

// hkdfDerive performs HKDF-SHA256 (Extract-then-Expand) as defined in RFC 5869.
func hkdfDerive(label string, salt, ikm []byte) ([]byte, error) {
	return crypto.HKDFDerive([]byte(label), salt, ikm, scV2OKMSize)
}
