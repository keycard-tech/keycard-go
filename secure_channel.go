package keycard

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/keycard-tech/keycard-go/apdu"
	"github.com/keycard-tech/keycard-go/crypto"
	"github.com/keycard-tech/keycard-go/globalplatform"
	"github.com/keycard-tech/keycard-go/types"
)

// Compile-time interface checks.
var (
	_ SecureChannel = (*SecureChannelV1)(nil)
	_ SecureChannel = (*SecureChannelV2)(nil)
)

// ============================================================================
// Secure Channel interface
// ============================================================================

// SecureChannel is the common interface for Secure Channel V1 and V2.
//
// Both implementations provide encrypted command/response transport.
// Methods that only apply to one version return an error on the other.
type SecureChannel interface {
	// AutoOpen performs the full handshake and opens the secure channel.
	AutoOpen(ch types.Channel) error

	// AutoPair performs the pairing procedure (V1 only).
	AutoPair(ch types.Channel, mode uint8, sharedSecret []byte) error

	// AutoUnpair unpairs the current paired key (V1 only).
	AutoUnpair(ch types.Channel) error

	// UnpairOthers unpairs all other clients (V1 only).
	UnpairOthers(ch types.Channel) error

	// OpenSecureChannel sends an OPEN SECURE CHANNEL APDU.
	OpenSecureChannel(ch types.Channel, index uint8, data []byte) (*apdu.Response, error)

	// MutuallyAuthenticate sends a MUTUALLY AUTHENTICATE APDU (V1 only).
	MutuallyAuthenticate(ch types.Channel) (*apdu.Response, error)

	// Pair sends a PAIR APDU (V1 only).
	Pair(ch types.Channel, p1, p2 uint8, data []byte) (*apdu.Response, error)

	// Unpair sends an UNPAIR APDU (V1 only).
	Unpair(ch types.Channel, p1 uint8) (*apdu.Response, error)

	// ProtectedCommand returns a command APDU with the secure channel wrapper
	// applied. Returns Err if the channel was previously established but is
	// not currently open — the caller must call AutoOpen again.
	ProtectedCommand(cla, ins, p1, p2 uint8, data []byte) (*apdu.Command, error)

	// Transmit sends a protected command APDU and unwraps the response.
	Transmit(ch types.Channel, cmd *apdu.Command) (*apdu.Response, error)

	// Pairing returns the current pairing data (V1 only, nil for V2).
	Pairing() *types.Pairing

	// SetPairing sets the pairing data (V1 only, no-op for V2).
	SetPairing(p *types.Pairing)

	// Reset resets the secure channel, invalidating the current session.
	Reset()

	// Version returns the protocol version of this secure channel.
	Version() SecureChannelVersion
}

// ============================================================================
// Secure Channel V1
// ============================================================================

// SecureChannelV1 implements the Secure Channel V1 protocol.
//
// Uses AES-256-CBC with AES-CBC-MAC for encryption and authentication,
// with pairing-based key derivation via ECDH on secp256k1.
type SecureChannelV1 struct {
	c           types.Channel
	open        bool
	established bool // true after the channel has ever been successfully opened
	secret      []byte
	publicKey   *ecdsa.PublicKey
	encKey      []byte
	macKey      []byte
	iv          []byte
	pairing     *types.Pairing
}

// NewSecureChannel creates a new SecureChannelV1.
func NewSecureChannel(c types.Channel) *SecureChannelV1 {
	return &SecureChannelV1{
		c: c,
	}
}

// GenerateSecret generates an ephemeral ECDH key pair and computes the
// shared secret with the card's static public key.
func (sc *SecureChannelV1) GenerateSecret(cardPubKeyData []byte) error {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		return err
	}

	cardPubKey, err := ethcrypto.UnmarshalPubkey(cardPubKeyData)
	if err != nil {
		return err
	}

	sc.publicKey = &key.PublicKey
	sc.secret = crypto.GenerateECDHSharedSecret(key, cardPubKey)

	return nil
}

// Secret returns the ECDH shared secret.
func (sc *SecureChannelV1) Secret() []byte {
	return sc.secret
}

// PublicKey returns the client's ephemeral public key.
func (sc *SecureChannelV1) PublicKey() *ecdsa.PublicKey {
	return sc.publicKey
}

// RawPublicKey returns the client's uncompressed public key (65 bytes).
func (sc *SecureChannelV1) RawPublicKey() []byte {
	return ethcrypto.FromECDSAPub(sc.publicKey)
}

// Init initializes the session keys directly (used by legacy OpenSecureChannel flow).
func (sc *SecureChannelV1) Init(iv, encKey, macKey []byte) {
	sc.iv = iv
	sc.encKey = encKey
	sc.macKey = macKey
	sc.open = true
	sc.established = true
}

// OneShotEncrypt encrypts init data for the INIT command.
//
// Uses the ECDH shared secret as the AES key with a random IV.
// Output format: [pub_key_len] || public_key || iv || encrypted_data
func (sc *SecureChannelV1) OneShotEncrypt(secrets *Secrets) ([]byte, error) {
	pubKeyData := ethcrypto.FromECDSAPub(sc.publicKey)
	data := append([]byte(secrets.Pin()), []byte(secrets.Puk())...)
	data = append(data, secrets.PairingToken()...)

	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
}

// encryptedInitPayload encrypts raw init data (PIN || PUK || shared_secret || extensions)
// using the ECDH shared secret for the INIT command.
//
// This is used by InitWithSecret/InitV2 for V1 cards.
func (sc *SecureChannelV1) encryptedInitPayload(data []byte) ([]byte, error) {
	pubKeyData := ethcrypto.FromECDSAPub(sc.publicKey)
	return crypto.OneShotEncrypt(pubKeyData, sc.secret, data)
}

// IsOpen returns true if the session is currently active.
func (sc *SecureChannelV1) IsOpen() bool {
	return sc.open
}

// ============================================================================
// SecureChannel interface implementation
// ============================================================================

// AutoOpen performs the full V1 secure channel handshake:
// 1. Send OPEN_SECURE_CHANNEL with pairing index + client public key
// 2. Derive session keys from response
// 3. Perform mutual authentication
func (sc *SecureChannelV1) AutoOpen(ch types.Channel) error {
	if sc.publicKey == nil {
		return errors.New("no public key available; call GenerateSecret first")
	}
	if sc.pairing == nil {
		return errors.New("no pairing data available; call SetPairing or AutoPair first")
	}

	// Step 1: Open secure channel
	resp, err := sc.OpenSecureChannel(ch, sc.pairing.Index(), sc.RawPublicKey())
	if err != nil {
		return err
	}
	if resp.Sw != apdu.SwOK {
		return apdu.NewErrBadResponse(resp.Sw, "OPEN_SECURE_CHANNEL failed")
	}
	if err := sc.processOpenResponse(resp.Data); err != nil {
		return err
	}

	// Step 2: Mutual authentication
	_, err = sc.MutuallyAuthenticate(ch)
	if err != nil {
		return err
	}

	sc.established = true
	return nil
}

// OpenSecureChannel sends an OPEN SECURE CHANNEL APDU.
func (sc *SecureChannelV1) OpenSecureChannel(ch types.Channel, index uint8, data []byte) (*apdu.Response, error) {
	sc.open = false
	cmd := apdu.NewCommand(globalplatform.ClaGp, InsOpenSecureChannel, index, 0, data)
	return ch.Send(cmd)
}

// MutuallyAuthenticate sends a MUTUALLY AUTHENTICATE APDU with a random challenge.
func (sc *SecureChannelV1) MutuallyAuthenticate(ch types.Channel) (*apdu.Response, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}

	cmd, err := sc.ProtectedCommand(globalplatform.ClaGp, InsMutuallyAuthenticate, 0, 0, data)
	if err != nil {
		return nil, err
	}
	resp, err := sc.Transmit(ch, cmd)
	if err != nil {
		return nil, err
	}
	if resp.Sw != apdu.SwOK {
		return nil, apdu.NewErrBadResponse(resp.Sw, "MUTUALLY_AUTHENTICATE failed")
	}
	if len(resp.Data) != 32 {
		return nil, errors.New("invalid authentication data from the card")
	}
	return resp, nil
}

// Pair sends a PAIR APDU.
func (sc *SecureChannelV1) Pair(ch types.Channel, p1, p2 uint8, data []byte) (*apdu.Response, error) {
	cmd := apdu.NewCommand(globalplatform.ClaGp, InsPair, p1, p2, data)
	return sc.Transmit(ch, cmd)
}

// Unpair sends an UNPAIR APDU.
func (sc *SecureChannelV1) Unpair(ch types.Channel, p1 uint8) (*apdu.Response, error) {
	cmd, err := sc.ProtectedCommand(globalplatform.ClaGp, InsUnpair, p1, 0, nil)
	if err != nil {
		return nil, err
	}
	return sc.Transmit(ch, cmd)
}

// AutoPair performs the full V1 pairing procedure.
func (sc *SecureChannelV1) AutoPair(ch types.Channel, mode uint8, sharedSecret []byte) error {
	// Generate random client challenge
	clientChallenge := make([]byte, 32)
	if _, err := rand.Read(clientChallenge); err != nil {
		return err
	}

	// Step 1: Send client challenge
	resp, err := sc.Pair(ch, 0x00, mode, clientChallenge)
	if err != nil {
		return err
	}
	if resp.Sw != apdu.SwOK {
		return apdu.NewErrBadResponse(resp.Sw, "PAIR step 1 failed")
	}

	respData := resp.Data
	if len(respData) < 64 {
		return errors.New("pairing response too short")
	}

	cardCryptogram := respData[:32]
	cardChallenge := respData[32:]

	// Verify card cryptogram: SHA-256(shared_secret || client_challenge)
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(clientChallenge)
	expected := h.Sum(nil)

	if !crypto.ConstantTimeCompare(cardCryptogram, expected) {
		return errors.New("invalid card cryptogram")
	}

	// Compute client cryptogram: SHA-256(shared_secret || card_challenge)
	h.Reset()
	h.Write(sharedSecret)
	h.Write(cardChallenge)
	clientCryptogram := h.Sum(nil)

	// Step 2: Send client cryptogram
	resp, err = sc.Pair(ch, 0x01, 0x00, clientCryptogram)
	if err != nil {
		return err
	}
	if resp.Sw != apdu.SwOK {
		return apdu.NewErrBadResponse(resp.Sw, "PAIR step 2 failed")
	}

	respData = resp.Data
	if len(respData) < 2 {
		return errors.New("pairing step 2 response too short")
	}

	pairingIndex := respData[0]

	// Derive pairing key: SHA-256(shared_secret || resp_data[1:])
	h.Reset()
	h.Write(sharedSecret)
	h.Write(respData[1:])
	derived := h.Sum(nil)

	var pairingKey [32]byte
	copy(pairingKey[:], derived)

	sc.pairing = types.NewPairing(pairingKey, pairingIndex)
	return nil
}

// AutoUnpair unpairs the current paired key.
func (sc *SecureChannelV1) AutoUnpair(ch types.Channel) error {
	if sc.pairing == nil {
		return errors.New("no pairing data available")
	}
	_, err := sc.Unpair(ch, sc.pairing.Index())
	return err
}

// UnpairOthers unpairs all other clients (all pairing slots except the current one).
func (sc *SecureChannelV1) UnpairOthers(ch types.Channel) error {
	currentIndex := byte(0xFF)
	if sc.pairing != nil {
		currentIndex = sc.pairing.Index()
	}

	for i := 0; i < PairingMaxClientCount; i++ {
		if byte(i) != currentIndex {
			cmd, err := sc.ProtectedCommand(globalplatform.ClaGp, InsUnpair, byte(i), 0, nil)
			if err != nil {
				return err
			}
			resp, err := sc.Transmit(ch, cmd)
			if err != nil {
				return err
			}
			if resp.Sw != apdu.SwOK {
				// Non-critical: some slots may not be paired
				_ = resp
			}
		}
	}
	return nil
}

// ProtectedCommand returns a command APDU with the V1 secure channel wrapper
// applied. If the channel is not open, returns the command as-is (plaintext).
// If the channel was previously established but is now closed, returns an error.
func (sc *SecureChannelV1) ProtectedCommand(cla, ins, p1, p2 uint8, data []byte) (*apdu.Command, error) {
	if !sc.open {
		if sc.established {
			return nil, errors.New("secure channel was closed after an error; call AutoOpen again before sending protected commands")
		}
		return apdu.NewCommand(cla, ins, p1, p2, data), nil
	}

	if sc.encKey == nil {
		return nil, errors.New("session encryption key not set")
	}

	// Encrypt data with AES-256-CBC using ISO 7816-4 padding
	encrypted, err := crypto.EncryptData(data, sc.encKey, sc.iv)
	if err != nil {
		return nil, err
	}

	// Build metadata for MAC: CLA | INS | P1 | P2 | (encrypted_len + IV_len) | zeros
	meta := make([]byte, 16)
	meta[0] = cla
	meta[1] = ins
	meta[2] = p1
	meta[3] = p2
	if len(encrypted)+16 > 255 {
		return nil, fmt.Errorf("protected command payload too large: encrypted length %d bytes", len(encrypted)+16)
	}
	meta[4] = byte(len(encrypted) + 16)

	// Update IV with MAC
	sc.updateIV(meta, encrypted)

	// Final data: iv || encrypted_data
	finalData := make([]byte, 0, 16+len(encrypted))
	finalData = append(finalData, sc.iv...)
	finalData = append(finalData, encrypted...)

	return apdu.NewCommand(cla, ins, p1, p2, finalData), nil
}

// Transmit sends a command and decrypts the response.
func (sc *SecureChannelV1) Transmit(ch types.Channel, cmd *apdu.Command) (*apdu.Response, error) {
	resp, err := ch.Send(cmd)
	if err != nil {
		sc.open = false
		return nil, err
	}

	// If security condition not satisfied, invalidate session
	if resp.Sw == SwSecurityConditionNotSatisfied {
		sc.open = false
	}

	if !sc.open {
		return resp, nil
	}

	if len(resp.Data) < 16 {
		sc.open = false
		return nil, errors.New("encrypted response too short")
	}

	// Response format: mac(16 bytes) || encrypted_data
	rmac := resp.Data[:16]
	rdata := resp.Data[16:]

	// Build metadata for MAC verification: (total_len) | zeros
	rmeta := make([]byte, 16)
	rmeta[0] = byte(len(resp.Data))

	// Decrypt
	plainData, err := crypto.DecryptData(rdata, sc.encKey, sc.iv)
	if err != nil {
		sc.open = false
		return nil, fmt.Errorf("AES-CBC decryption failed: %w", err)
	}

	// Update IV with MAC
	sc.updateIV(rmeta, rdata)

	// Verify MAC
	if !crypto.ConstantTimeCompare(sc.iv, rmac) {
		sc.open = false
		return nil, errors.New("invalid response MAC")
	}

	return apdu.ParseResponse(plainData)
}

// Pairing returns the current pairing data.
func (sc *SecureChannelV1) Pairing() *types.Pairing {
	return sc.pairing
}

// SetPairing sets the pairing data.
func (sc *SecureChannelV1) SetPairing(p *types.Pairing) {
	sc.pairing = p
}

// Reset resets the secure channel, invalidating the current session.
func (sc *SecureChannelV1) Reset() {
	sc.open = false
	sc.established = false
	if sc.encKey != nil {
		crypto.Zeroize(sc.encKey)
		sc.encKey = nil
	}
	if sc.macKey != nil {
		crypto.Zeroize(sc.macKey)
		sc.macKey = nil
	}
	sc.iv = nil
}

// Version returns the secure channel protocol version.
func (sc *SecureChannelV1) Version() SecureChannelVersion {
	return VersionV1
}

// Send is a convenience method that wraps ProtectedCommand + Transmit.
//
// Deprecated: use ProtectedCommand + Transmit directly for new code.
func (sc *SecureChannelV1) Send(cmd *apdu.Command) (*apdu.Response, error) {
	protected, err := sc.ProtectedCommand(cmd.Cla, cmd.Ins, cmd.P1, cmd.P2, cmd.Data)
	if err != nil {
		return nil, err
	}
	return sc.Transmit(sc.c, protected)
}

// ============================================================================
// Internal helpers
// ============================================================================

// processOpenResponse processes the OPEN SECURE CHANNEL response to derive
// session keys.
//
// Response format: card_data(32 bytes) || iv(16 bytes)
func (sc *SecureChannelV1) processOpenResponse(data []byte) error {
	if sc.secret == nil {
		return errors.New("no ECDH secret available")
	}
	if sc.pairing == nil {
		return errors.New("no pairing data available")
	}
	if len(data) < 48 {
		return errors.New("OPEN_SECURE_CHANNEL response too short")
	}

	pairingKey := sc.pairing.Key()
	encKey, macKey, iv := crypto.DeriveSessionKeys(sc.secret, pairingKey[:], data)
	sc.encKey = encKey
	sc.macKey = macKey
	sc.iv = iv
	sc.open = true

	return nil
}

// updateIV computes AES-CBC-MAC over meta || data and stores result as new IV.
func (sc *SecureChannelV1) updateIV(meta, data []byte) {
	mac, err := crypto.CalculateMAC(meta, data, sc.macKey)
	if err != nil {
		sc.open = false
		return
	}
	sc.iv = mac
}
