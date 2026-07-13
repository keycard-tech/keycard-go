package keycard

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/crypto"
	"github.com/status-im/keycard-go/derivationpath"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/identifiers"
	"github.com/status-im/keycard-go/types"
)

var ErrNoAvailablePairingSlots = errors.New("no available pairing slots")
var ErrBadChecksumSize = errors.New("bad checksum size")

// WrongPINError is returned when a PIN verification fails.
type WrongPINError struct {
	RemainingAttempts int
}

func (e *WrongPINError) Error() string {
	return fmt.Sprintf("wrong pin. remaining attempts: %d", e.RemainingAttempts)
}

// WrongPUKError is returned when a PUK verification fails.
type WrongPUKError struct {
	RemainingAttempts int
}

func (e *WrongPUKError) Error() string {
	return fmt.Sprintf("wrong puk. remaining attempts: %d", e.RemainingAttempts)
}

// CommandSet is the main API for interacting with a Status Keycard.
//
// The secure channel version (V1 or V2) is auto-detected based on the applet
// version after the first Select() call.
type CommandSet struct {
	c               types.Channel
	sc              SecureChannel
	ApplicationInfo *types.ApplicationInfo
	PairingInfo     *types.PairingInfo // legacy, kept for backward compatibility
	caPublicKeys    [][33]byte
	whitelistedKeys [][33]byte
}

// NewCommandSet creates a CommandSet using the given APDU channel.
//
// Uses the default Status CA public key for V2 certificate verification.
func NewCommandSet(c types.Channel) *CommandSet {
	return NewCommandSetWithCA(c, DefaultCAPublicKey)
}

// NewCommandSetWithCA creates a CommandSet with a single trusted CA public key.
func NewCommandSetWithCA(c types.Channel, caPublicKey [33]byte) *CommandSet {
	return NewCommandSetWithCAs(c, [][33]byte{caPublicKey}, nil)
}

// NewCommandSetWithCAs creates a CommandSet with custom trusted CA keys and
// optionally whitelisted card identity keys.
func NewCommandSetWithCAs(c types.Channel, caPublicKeys, whitelistedCardKeys [][33]byte) *CommandSet {
	return &CommandSet{
		c:               c,
		sc:              NewSecureChannelV2(caPublicKeys, whitelistedCardKeys),
		ApplicationInfo: &types.ApplicationInfo{},
		caPublicKeys:    caPublicKeys,
		whitelistedKeys: whitelistedCardKeys,
	}
}

// SetPairingInfo sets the legacy pairing info.
//
// Deprecated: use SetPairing instead.
func (cs *CommandSet) SetPairingInfo(key []byte, index int) {
	cs.PairingInfo = &types.PairingInfo{
		Key:   key,
		Index: index,
	}
}

// Select selects the default instance (index 1) of the Keycard applet.
//
// Parses the response as ApplicationInfo and auto-selects the correct
// secure channel version (V1 or V2) based on applet version.
func (cs *CommandSet) Select() error {
	return cs.selectWithIndex(uint8(identifiers.KeycardDefaultInstanceIndex))
}

func (cs *CommandSet) selectWithIndex(instanceIdx uint8) error {
	instanceAID, err := identifiers.KeycardInstanceAID(int(instanceIdx))
	if err != nil {
		return err
	}

	cmd := globalplatform.NewCommandSelect(instanceAID)
	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	appInfo, err := types.ParseApplicationInfo(resp.Data)
	if err != nil {
		return err
	}

	cs.ApplicationInfo = appInfo

	if cs.ApplicationInfo.HasSecureChannelCapability() {
		if cs.isSecureChannelV2() {
			// V2: create new SecureChannelV2
			scV2 := NewSecureChannelV2(cs.caPublicKeys, cs.whitelistedKeys)
			if len(appInfo.CertData) > 0 {
				if err := scV2.SetCardCertificate(appInfo.CertData); err != nil {
					return fmt.Errorf("failed to set card certificate: %w", err)
				}
			}
			cs.sc = scV2
		} else {
			// V1: create new SecureChannelV1 and generate ECDH secret
			scV1 := NewSecureChannel(cs.c)
			if err := scV1.GenerateSecret(cs.ApplicationInfo.SecureChannelPublicKey); err != nil {
				return err
			}
			scV1.Reset()
			cs.sc = scV1
		}
	}

	return nil
}

// isSecureChannelV2 returns true if the applet uses Secure Channel V2
// (app version >= 4.0).
func (cs *CommandSet) isSecureChannelV2() bool {
	return cs.ApplicationInfo.AppVersion() >= 0x0400
}

// sendProtected wraps data in the secure channel (CLA 0x80) and transmits it.
func (cs *CommandSet) sendProtected(ins, p1, p2 uint8, data []byte) (*apdu.Response, error) {
	cmd, err := cs.sc.ProtectedCommand(globalplatform.ClaGp, ins, p1, p2, data)
	if err != nil {
		return nil, err
	}
	return cs.sc.Transmit(cs.c, cmd)
}

// Init initializes the card with the given secrets.
//
// For V1 cards, uses OneShotEncrypt (encrypt with ECDH secret, send as raw command).
// For V2 cards, opens the secure channel first then sends INIT as an encrypted command.
func (cs *CommandSet) Init(secrets *Secrets) error {
	// V1: use OneShotEncrypt (legacy flow)
	if scV1, ok := cs.sc.(*SecureChannelV1); ok {
		data, err := scV1.OneShotEncrypt(secrets)
		if err != nil {
			return err
		}
		initCmd := NewCommandInit(data)
		resp, err := cs.c.Send(initCmd)
		return cs.checkOK(resp, err)
	}

	// V2: open secure channel first, then send INIT as protected command
	if err := cs.sc.AutoOpen(cs.c); err != nil {
		return err
	}
	initData := cs.buildInitData(secrets.Pin(), secrets.Puk(), secrets.PairingToken(), nil, 0, 0)
	_, err := cs.sendProtected(InsInit, 0, 0, initData)
	return err
}

// InitWithSecret initializes the card with a raw shared secret.
func (cs *CommandSet) InitWithSecret(pin, puk string, sharedSecret []byte) error {
	return cs.initWithSecret(pin, nil, puk, sharedSecret, 0, 0)
}

// InitV2 initializes the card without a pairing password (V2 only).
//
// Secure Channel V2 does not use a shared secret for pairing, so this
// convenience method initializes the card with an empty shared secret.
// For V1 cards, use Init or InitWithSecret instead.
func (cs *CommandSet) InitV2(pin, puk string) error {
	return cs.initWithSecret(pin, nil, puk, []byte{}, 0, 0)
}

// InitWithOptions initializes the card with optional alt PIN and retry counts.
func (cs *CommandSet) InitWithOptions(pin, altPin, puk, pairingPass string, pinRetries, pukRetries uint8) error {
	sharedSecret := PairingPasswordToSecret(pairingPass)
	return cs.initWithSecret(pin, &altPin, puk, sharedSecret, pinRetries, pukRetries)
}

func (cs *CommandSet) initWithSecret(pin string, altPin *string, puk string, sharedSecret []byte, pinRetries, pukRetries uint8) error {
	initData := cs.buildInitData(pin, puk, sharedSecret, altPin, pinRetries, pukRetries)

	// V2: open secure channel first, then send INIT as encrypted command
	if _, ok := cs.sc.(*SecureChannelV2); ok {
		if err := cs.sc.AutoOpen(cs.c); err != nil {
			return err
		}
		_, err := cs.sendProtected(InsInit, 0, 0, initData)
		return err
	}

	// V1: use OneShotEncrypt
	scV1, ok := cs.sc.(*SecureChannelV1)
	if !ok {
		return errors.New("expected SecureChannelV1 for init with secret")
	}
	encrypted, err := scV1.encryptedInitPayload(initData)
	if err != nil {
		return err
	}
	initCmd := NewCommandInit(encrypted)
	resp, err := cs.c.Send(initCmd)
	return cs.checkOK(resp, err)
}

// buildInitData builds the init payload: PIN || PUK || shared_secret || [pin_retries, puk_retries] || [alt_pin]
func (cs *CommandSet) buildInitData(pin, puk string, sharedSecret []byte, altPin *string, pinRetries, pukRetries uint8) []byte {
	baseLen := len(pin) + len(puk) + len(sharedSecret)
	extLen := 0
	if altPin != nil && *altPin != "" {
		extLen = 2 + len(*altPin)
	} else if pinRetries != 0 || pukRetries != 0 {
		extLen = 2
	}

	initData := make([]byte, 0, baseLen+extLen)
	initData = append(initData, []byte(pin)...)
	initData = append(initData, []byte(puk)...)
	initData = append(initData, sharedSecret...)

	if extLen > 0 {
		initData = append(initData, pinRetries, pukRetries)
		if altPin != nil && *altPin != "" {
			initData = append(initData, []byte(*altPin)...)
		}
	}

	return initData
}

// Pair pairs the card using a pairing password (V1 only, legacy PBKDF2-based flow).
//
// Deprecated: use AutoPairWithMode for new code.
func (cs *CommandSet) Pair(pairingPass string) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	cmd := NewCommandPairFirstStep(challenge)
	resp, err := cs.c.Send(cmd)
	if resp != nil && resp.Sw == SwNoAvailablePairingSlots {
		return ErrNoAvailablePairingSlots
	}

	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	cardCryptogram := resp.Data[:32]
	cardChallenge := resp.Data[32:]

	secretHash, err := crypto.VerifyCryptogram(challenge, pairingPass, cardCryptogram)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(secretHash[:])
	h.Write(cardChallenge)
	cmd = NewCommandPairFinalStep(h.Sum(nil))
	resp, err = cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	h.Reset()
	h.Write(secretHash[:])
	h.Write(resp.Data[1:])

	pairingKey := h.Sum(nil)
	pairingIndex := resp.Data[0]

	cs.PairingInfo = &types.PairingInfo{
		Key:   pairingKey,
		Index: int(pairingIndex),
	}

	return nil
}

// AutoPairWithMode pairs the card using a pairing password with explicit mode.
func (cs *CommandSet) AutoPairWithMode(pairingPass string, mode uint8) error {
	secret := PairingPasswordToSecret(pairingPass)
	return cs.AutoPairWithSecretAndMode(secret, mode)
}

// AutoPairWithSecret pairs the card using a raw binary shared secret.
func (cs *CommandSet) AutoPairWithSecret(sharedSecret []byte) error {
	return cs.AutoPairWithSecretAndMode(sharedSecret, P2PairAny)
}

// AutoPairWithSecretAndMode pairs the card using a raw binary shared secret with explicit mode.
func (cs *CommandSet) AutoPairWithSecretAndMode(sharedSecret []byte, mode uint8) error {
	if err := cs.sc.AutoPair(cs.c, mode, sharedSecret); err != nil {
		return err
	}
	pairing := cs.sc.Pairing()
	if pairing != nil {
		keyArr := pairing.Key()
		cs.PairingInfo = &types.PairingInfo{
			Key:   keyArr[:],
			Index: int(pairing.Index()),
		}
	}
	return nil
}

// Unpair removes a pairing by index (V1 only).
func (cs *CommandSet) Unpair(index uint8) error {
	_, err := cs.sc.Unpair(cs.c, index)
	return err
}

// UnpairOthers unpairs all other clients (V1 only).
func (cs *CommandSet) UnpairOthers() error {
	return cs.sc.UnpairOthers(cs.c)
}

// Identify sends an IDENTIFY CARD command and verifies the card's identity.
func (cs *CommandSet) Identify() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	resp, err := cs.sendProtected(InsIdentify, 0, 0, challenge)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.VerifyIdentity(challenge, resp.Data)
}

// OpenSecureChannel opens the secure channel using V1 pairing-based flow.
//
// For V2 cards, use AutoOpenSecureChannel instead.
func (cs *CommandSet) OpenSecureChannel() error {
	if cs.ApplicationInfo == nil {
		return errors.New("cannot open secure channel without application info")
	}
	if cs.PairingInfo == nil {
		return errors.New("cannot open secure channel without pairing info")
	}

	// V1 flow
	scV1, ok := cs.sc.(*SecureChannelV1)
	if !ok {
		return errors.New("OpenSecureChannel is for V1 cards; use AutoOpenSecureChannel for V2")
	}

	var pairingKey [32]byte
	copy(pairingKey[:], cs.PairingInfo.Key)
	scV1.SetPairing(types.NewPairing(pairingKey, uint8(cs.PairingInfo.Index)))

	cmd := NewCommandOpenSecureChannel(uint8(cs.PairingInfo.Index), scV1.RawPublicKey())
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return err
	}

	encKey, macKey, iv := crypto.DeriveSessionKeys(scV1.Secret(), cs.PairingInfo.Key, resp.Data)
	scV1.Init(iv, encKey, macKey)

	err = cs.mutualAuthenticate()
	if err != nil {
		return err
	}

	return nil
}

// AutoOpenSecureChannel opens the secure channel using the auto-detected version.
func (cs *CommandSet) AutoOpenSecureChannel() error {
	return cs.sc.AutoOpen(cs.c)
}

// GetStatus returns the application status for the given info type.
func (cs *CommandSet) GetStatus(info uint8) (*types.ApplicationStatus, error) {
	resp, err := cs.sendProtected(InsGetStatus, info, 0, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseApplicationStatus(resp.Data)
}

// GetStatusApplication returns the application-level status.
func (cs *CommandSet) GetStatusApplication() (*types.ApplicationStatus, error) {
	return cs.GetStatus(P1GetStatusApplication)
}

// GetStatusKeyPath returns the key-path status.
func (cs *CommandSet) GetStatusKeyPath() (*types.ApplicationStatus, error) {
	return cs.GetStatus(P1GetStatusKeyPath)
}

// VerifyPIN verifies the user PIN.
func (cs *CommandSet) VerifyPIN(pin string) error {
	resp, err := cs.sendProtected(InsVerifyPIN, 0, 0, []byte(pin))
	if err = cs.checkOK(resp, err); err != nil {
		if resp != nil && ((resp.Sw & 0x63C0) == 0x63C0) {
			remainingAttempts := resp.Sw & 0x000F
			return &WrongPINError{
				RemainingAttempts: int(remainingAttempts),
			}
		}
		return err
	}

	return nil
}

// ChangePIN changes the user PIN.
func (cs *CommandSet) ChangePIN(pin string) error {
	resp, err := cs.sendProtected(InsChangePIN, P1ChangePinPIN, 0, []byte(pin))
	return cs.checkOK(resp, err)
}

// UnblockPIN unblocks the PIN using the PUK and a new PIN.
func (cs *CommandSet) UnblockPIN(puk string, newPIN string) error {
	data := append([]byte(puk), []byte(newPIN)...)
	resp, err := cs.sendProtected(InsUnblockPIN, 0, 0, data)
	if err = cs.checkOK(resp, err); err != nil {
		if resp != nil && ((resp.Sw & 0x63C0) == 0x63C0) {
			remainingAttempts := resp.Sw & 0x000F
			return &WrongPUKError{
				RemainingAttempts: int(remainingAttempts),
			}
		}
		return err
	}

	return nil
}

// ChangePUK changes the PUK.
func (cs *CommandSet) ChangePUK(puk string) error {
	resp, err := cs.sendProtected(InsChangePIN, P1ChangePinPUK, 0, []byte(puk))
	return cs.checkOK(resp, err)
}

// ChangePairingSecret changes the pairing secret (legacy, uses PBKDF2 from secrets.go).
//
// Deprecated: use ChangePairingPassword instead.
func (cs *CommandSet) ChangePairingSecret(password string) error {
	secret := generatePairingToken(password)
	resp, err := cs.sendProtected(InsChangePIN, P1ChangePinPairingSecret, 0, secret)
	return cs.checkOK(resp, err)
}

// ChangePairingPassword changes the pairing password.
func (cs *CommandSet) ChangePairingPassword(password string) error {
	secret := PairingPasswordToSecret(password)
	resp, err := cs.sendProtected(InsChangePIN, P1ChangePinPairingSecret, 0, secret)
	return cs.checkOK(resp, err)
}

// GenerateKey generates a new key on the card.
func (cs *CommandSet) GenerateKey() ([]byte, error) {
	resp, err := cs.sendProtected(InsGenerateKey, 0, 0, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// GenerateMnemonic generates a mnemonic on the card.
func (cs *CommandSet) GenerateMnemonic(checksumSize int) ([]int, error) {
	if checksumSize < 4 || checksumSize > 8 {
		return nil, ErrBadChecksumSize
	}

	resp, err := cs.sendProtected(InsGenerateMnemonic, byte(checksumSize), 0, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return parseMnemonicResponse(resp.Data)
}

func parseMnemonicResponse(data []byte) ([]int, error) {
	indexes := make([]int, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		index := int(data[i])<<8 | int(data[i+1])
		indexes = append(indexes, index)
	}
	return indexes, nil
}

// RemoveKey removes the current key from the card.
func (cs *CommandSet) RemoveKey() error {
	resp, err := cs.sendProtected(InsRemoveKey, 0, 0, nil)
	return cs.checkOK(resp, err)
}

// DeriveKey derives a key at the given BIP32 path.
func (cs *CommandSet) DeriveKey(path string) error {
	kp, err := derivationpath.KeyPathFromString(path)
	if err != nil {
		return err
	}
	resp, err := cs.sendProtected(InsDeriveKey, uint8(kp.Source()), 0, kp.Data())
	return cs.checkOK(resp, err)
}

// LoadSeed loads a BIP32 seed onto the card.
func (cs *CommandSet) LoadSeed(seed []byte) ([]byte, error) {
	resp, err := cs.sendProtected(InsLoadKey, P1LoadKeySeed, 0, seed)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// LoadKeyBIP32 loads a BIP32 keypair onto the card (includes public key).
func (cs *CommandSet) LoadKeyBIP32(keyPair *types.Bip32KeyPair) error {
	return cs.loadKeyBIP32Inner(keyPair, false)
}

// LoadKeyBIP32OmitPublic loads a BIP32 keypair onto the card (omits public key).
func (cs *CommandSet) LoadKeyBIP32OmitPublic(keyPair *types.Bip32KeyPair) error {
	return cs.loadKeyBIP32Inner(keyPair, true)
}

func (cs *CommandSet) loadKeyBIP32Inner(keyPair *types.Bip32KeyPair, omitPublic bool) error {
	includePublic := !omitPublic
	p1 := uint8(P1LoadKeyEC)
	if keyPair.IsExtended() {
		p1 = P1LoadKeyECExtended
	}
	keyTLV := keyPair.ToTLV(includePublic)
	resp, err := cs.sendProtected(InsLoadKey, p1, 0, keyTLV)
	return cs.checkOK(resp, err)
}

// LoadLEEKey loads an LEE seed onto the card.
func (cs *CommandSet) LoadLEEKey(seed []byte) error {
	resp, err := cs.sendProtected(InsLoadKey, P1LoadKeyLEE, 0, seed)
	return cs.checkOK(resp, err)
}

// ExportKey exports a key at the given path.
//
// Deprecated: use ExportKeyExtended for the new API.
func (cs *CommandSet) ExportKey(derive bool, makeCurrent bool, onlyPublic bool, path string) ([]byte, []byte, error) {
	var p2 uint8
	if onlyPublic {
		p2 = P2ExportKeyPublicOnly
	} else {
		p2 = P2ExportKeyPrivateAndPublic
	}

	key, err := cs.ExportKeyExtended(derive, makeCurrent, p2, path)
	if err != nil {
		return nil, nil, err
	}

	return key.PrivKey(), key.PubKey(), nil
}

// ExportKeyExtended exports a key at the given path with explicit P2.
func (cs *CommandSet) ExportKeyExtended(derive bool, makeCurrent bool, p2 uint8, path string) (*types.ExportedKey, error) {
	return cs.ExportKeyWithP2(derive, makeCurrent, p2, path)
}

// ExportCurrentKey exports the current key.
func (cs *CommandSet) ExportCurrentKey(publicOnly bool) (*types.ExportedKey, error) {
	p2 := uint8(P2ExportKeyPrivateAndPublic)
	if publicOnly {
		p2 = P2ExportKeyPublicOnly
	}
	resp, err := cs.sendProtected(InsExportKey, P1ExportKeyCurrent, p2, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}
	return types.ParseExportKeyResponse(resp.Data)
}

// ExportKeyWithP2 exports a key at the given path with explicit P2.
func (cs *CommandSet) ExportKeyWithP2(derive, makeCurrent bool, p2 uint8, path string) (*types.ExportedKey, error) {
	kp, err := derivationpath.KeyPathFromString(path)
	if err != nil {
		return nil, err
	}

	p1 := kp.Source()
	if derive {
		if makeCurrent {
			p1 |= P1ExportKeyDeriveAndMakeCurrent
		} else {
			p1 |= P1ExportKeyDerive
		}
	}

	resp, err := cs.sendProtected(InsExportKey, p1, p2, kp.Data())
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseExportKeyResponse(resp.Data)
}

// ExportLEEKey exports an LEE key at the given BIP32 path.
func (cs *CommandSet) ExportLEEKey(keypath string) ([]byte, error) {
	kp, err := derivationpath.KeyPathFromString(keypath)
	if err != nil {
		return nil, err
	}
	resp, err := cs.sendProtected(InsExportLEE, kp.Source(), 0, kp.Data())
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// ExportBIP85 exports a BIP85 derived key at the given path.
func (cs *CommandSet) ExportBIP85(keypath string, length uint8) ([]byte, error) {
	kp, err := derivationpath.KeyPathFromString(keypath)
	if err != nil {
		return nil, err
	}
	resp, err := cs.sendProtected(InsExportBIP85, length, 0, kp.Data())
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// SetPinlessPath sets the pinless signing path.
func (cs *CommandSet) SetPinlessPath(path string) error {
	kp, err := derivationpath.KeyPathFromString(path)
	if err != nil {
		return err
	}
	if kp.Source() != derivationpath.SourceMaster {
		return errors.New("pinless path must be set with an absolute path")
	}
	resp, err := cs.sendProtected(InsSetPinlessPath, 0, 0, kp.Data())
	return cs.checkOK(resp, err)
}

// ResetPinlessPath clears the pinless signing path.
func (cs *CommandSet) ResetPinlessPath() error {
	resp, err := cs.sendProtected(InsSetPinlessPath, 0, 0, nil)
	return cs.checkOK(resp, err)
}

// Sign signs a 32-byte hash with the current key (ECDSA).
func (cs *CommandSet) Sign(data []byte) (*types.Signature, error) {
	resp, err := cs.sendProtected(InsSign, P1SignCurrentKey, P2SignECDSA, data)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

// SignWithPath signs a 32-byte hash with a derived key path (ECDSA).
func (cs *CommandSet) SignWithPath(data []byte, path string) (*types.Signature, error) {
	return cs.SignWithPathAndAlgo(data, path, P2SignECDSA)
}

// SignWithPathAndAlgo signs a 32-byte hash with a derived key path and explicit algorithm.
func (cs *CommandSet) SignWithPathAndAlgo(data []byte, path string, algo uint8) (*types.Signature, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("data length must be 32, got %d", len(data))
	}

	kp, err := derivationpath.KeyPathFromString(path)
	if err != nil {
		return nil, err
	}

	// Build data: hash || path_data
	cmdData := make([]byte, 0, len(data)+len(kp.Data()))
	cmdData = append(cmdData, data...)
	cmdData = append(cmdData, kp.Data()...)

	p1 := uint8(kp.Source()) | P1SignDerive

	resp, err := cs.sendProtected(InsSign, p1, algo, cmdData)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

// SignPinless signs using the pinless path (no secure channel needed).
func (cs *CommandSet) SignPinless(data []byte) (*types.Signature, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("data length must be 32, got %d", len(data))
	}

	cmd := apdu.NewCommand(globalplatform.ClaGp, InsSign, P1SignPinless, P2SignECDSA, data)
	resp, err := cs.c.Send(cmd)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}

// GetData retrieves stored data by type.
func (cs *CommandSet) GetData(typ uint8) ([]byte, error) {
	resp, err := cs.sendProtected(InsGetData, typ, 0, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// StoreData stores data by type at offset 0.
func (cs *CommandSet) StoreData(typ uint8, data []byte) error {
	resp, err := cs.sendProtected(InsStoreData, typ, 0, data)
	return cs.checkOK(resp, err)
}

// StoreDataWithOffset stores data by type at an explicit offset.
// Offset must be a multiple of 4.
func (cs *CommandSet) StoreDataWithOffset(typ uint8, data []byte, offset uint16) error {
	resp, err := cs.sendProtected(InsStoreData, typ, byte(offset/4), data)
	return cs.checkOK(resp, err)
}

// SetNDEF sets the NDEF message on the card.
//
// For app version > 2.x, data is chunked and stored via STORE_DATA.
// For app version <= 2.x, data is sent directly via the legacy SET_NDEF command.
func (cs *CommandSet) SetNDEF(ndef []byte) error {
	appMajor := uint8(0)
	if cs.ApplicationInfo != nil {
		appMajor = uint8(cs.ApplicationInfo.AppVersion() >> 8)
	}

	if appMajor > 2 {
		// Ensure 2-byte length prefix
		data := make([]byte, len(ndef))
		copy(data, ndef)

		hasPrefix := len(data) >= 2
		if hasPrefix {
			expectedLen := int(data[0])<<8 | int(data[1])
			if expectedLen != len(data)-2 {
				hasPrefix = false
			}
		}
		if !hasPrefix {
			prefixed := make([]byte, 2+len(ndef))
			prefixed[0] = byte(len(ndef) >> 8)
			prefixed[1] = byte(len(ndef) & 0xFF)
			copy(prefixed[2:], ndef)
			data = prefixed
		}

		off := 0
		remaining := len(data)
		for remaining > 0 {
			chunkSize := NDEFMaxChunkSize
			if remaining < chunkSize {
				chunkSize = remaining
			}
			chunk := data[off : off+chunkSize]
			if err := cs.StoreDataWithOffset(P1StoreDataNDEF, chunk, uint16(off)); err != nil {
				return err
			}
			off += chunkSize
			remaining -= chunkSize
		}
		return nil
	}

	// Legacy SET_NDEF (app version <= 2.x)
	resp, err := cs.sendProtected(InsSetNDEF, 0, 0, ndef)
	return cs.checkOK(resp, err)
}

// GetChallenge requests a random challenge from the card.
func (cs *CommandSet) GetChallenge(length uint8) ([]byte, error) {
	resp, err := cs.sendProtected(InsGetChallenge, length, 0, nil)
	if err = cs.checkOK(resp, err); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// FactoryReset sends the FACTORY RESET command (unencrypted).
func (cs *CommandSet) FactoryReset() error {
	cmd := NewCommandFactoryReset()
	resp, err := cs.c.Send(cmd)
	return cs.checkOK(resp, err)
}

// -----------------------------------------------------------------------
// Accessors
// -----------------------------------------------------------------------

// AppInfo returns the application info from the last SELECT command.
func (cs *CommandSet) AppInfo() *types.ApplicationInfo {
	return cs.ApplicationInfo
}

// SecureChannelVersion returns the secure channel version in use.
//
// Returns (VersionV1, true) or (VersionV2, true) if secure channel is
// supported, or (VersionV1, false) if the applet has not been selected yet.
func (cs *CommandSet) SecureChannelVersion() (SecureChannelVersion, bool) {
	if cs.ApplicationInfo == nil || !cs.ApplicationInfo.HasSecureChannelCapability() {
		return VersionV1, false
	}
	return cs.sc.Version(), true
}

// Pairing returns the current pairing data (V1 only, nil for V2).
func (cs *CommandSet) Pairing() *types.Pairing {
	return cs.sc.Pairing()
}

// SetPairing sets the pairing data (V1 only, no-op for V2).
func (cs *CommandSet) SetPairing(p *types.Pairing) {
	cs.sc.SetPairing(p)
}

// PairingPasswordToSecret converts a pairing password to a binary pairing
// secret via PBKDF2-HMAC-SHA256.
func PairingPasswordToSecret(password string) []byte {
	return generatePairingToken(password)
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

func (cs *CommandSet) mutualAuthenticate() error {
	resp, err := cs.sendProtected(InsMutuallyAuthenticate, 0, 0, nil)
	return cs.checkOK(resp, err)
}

func (cs *CommandSet) checkOK(resp *apdu.Response, err error, allowedResponses ...uint16) error {
	if err != nil {
		return err
	}

	if len(allowedResponses) == 0 {
		allowedResponses = []uint16{apdu.SwOK}
	}

	for _, code := range allowedResponses {
		if code == resp.Sw {
			return nil
		}
	}

	return apdu.NewErrBadResponse(resp.Sw, "unexpected response")
}
