package keycard

import "github.com/keycard-tech/keycard-go/v4/globalplatform"

// ============================================================================
// AIDs
// ============================================================================

// PackageAID is the AID for the Keycard package.
var PackageAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01}

// KeycardAID is the AID for the Keycard applet.
var KeycardAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01}

// KeycardDefaultInstanceIdx is the default instance index for Keycard.
const KeycardDefaultInstanceIdx = 1

// NDEFAID is the AID for NDEF.
var NDEFAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x02}

// NDEFInstanceAID is the NDEF instance AID.
var NDEFInstanceAID = []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}

// KeycardInstanceAID returns the instance AID for a specific Keycard instance.
// Panics if instanceIdx is 0.
func KeycardInstanceAID(instanceIdx uint8) []byte {
	if instanceIdx == 0 {
		panic("instance index must be between 1 and 255")
	}
	aid := make([]byte, len(KeycardAID)+1)
	copy(aid, KeycardAID)
	aid[len(KeycardAID)] = instanceIdx
	return aid
}

// ============================================================================
// INS codes
// ============================================================================

// Keycard applet INS codes.
const (
	InsInit                 = 0xFE
	InsFactoryReset         = 0xFD
	InsGetStatus            = 0xF2
	InsSetNDEF              = 0xF3 // Legacy SET_NDEF (app version <= 2.x)
	InsIdentify             = 0x14
	InsVerifyPIN            = 0x20
	InsChangePIN            = 0x21
	InsUnblockPIN           = 0x22
	InsLoadKey              = 0xD0
	InsDeriveKey            = 0xD1
	InsGenerateMnemonic     = 0xD2
	InsRemoveKey            = 0xD3
	InsGenerateKey          = 0xD4
	InsSign                 = 0xC0
	InsSetPinlessPath       = 0xC1
	InsExportKey            = 0xC2
	InsExportLEE            = 0xC3 // Export LEE key
	InsExportBIP85          = 0xC4 // Export BIP85 derived key
	InsGetData              = 0xCA
	InsStoreData            = 0xE2
	InsGetChallenge         = 0x84 // Get challenge

	// Secure Channel V1 INS codes.
	InsOpenSecureChannel    = 0x10
	InsMutuallyAuthenticate = 0x11
	InsPair                 = 0x12
	InsUnpair               = 0x13

	// Secure Channel V2 INS codes.
	InsSecuredAPDU          = 0x18 // V2 encrypted command wrapper
)

// ============================================================================
// P1/P2 parameter constants
// ============================================================================

// CHANGE_PIN P1 values.
const (
	P1ChangePinPIN             = 0x00
	P1ChangePinPUK             = 0x01
	P1ChangePinPairingSecret   = 0x02
)

// GET_STATUS P1 values.
const (
	P1GetStatusApplication = 0x00
	P1GetStatusKeyPath     = 0x01
)

// LOAD_KEY P1 values.
const (
	P1LoadKeyEC         = 0x01
	P1LoadKeyECExtended = 0x02
	P1LoadKeySeed       = 0x03
	P1LoadKeyLEE        = 0x04
)

// DERIVE_KEY P1 source values.
const (
	P1DeriveKeyFromMaster    = 0x00
	P1DeriveKeyFromParent    = 0x40
	P1DeriveKeyFromCurrent   = 0x80
)

// SIGN P1 values.
const (
	P1SignCurrentKey          = 0x00
	P1SignDerive              = 0x01
	P1SignDeriveAndMakeCurrent = 0x02
	P1SignPinless             = 0x03
)

// SIGN P2 algorithm values.
const (
	P2SignECDSA          = 0x00
	P2SignEdDSAEd25519   = 0x01
	P2SignBLS12_381      = 0x02
	P2SignBIP340Schnorr  = 0x03
)

// STORE_DATA P1 data type values.
const (
	P1StoreDataPublic = 0x00
	P1StoreDataNDEF   = 0x01
	P1StoreDataCash   = 0x02
)

// EXPORT_KEY P1 values.
const (
	P1ExportKeyCurrent            = 0x00
	P1ExportKeyDerive             = 0x01
	P1ExportKeyDeriveAndMakeCurrent = 0x02
)

// EXPORT_KEY P2 values.
const (
	P2ExportKeyPrivateAndPublic = 0x00
	P2ExportKeyPublicOnly       = 0x01
	P2ExportKeyExtendedPublic   = 0x02
)

// PAIR P1 values.
const (
	P1PairingFirstStep  = 0x00
	P1PairingFinalStep  = 0x01
)

// PAIR P2 mode values.
const (
	P2PairAny        = 0x00
	P2PairEphemeral  = 0x01
	P2PairPersistent = 0x02
)

// FACTORY_RESET magic values.
const (
	P1FactoryResetMagic = 0xAA
	P2FactoryResetMagic = 0x55
)

// GENERATE_MNEMONIC P1 word count values.
const (
	P1GenerateMnemonicWords12 = 0x04 // 12 words (128 bits entropy)
	P1GenerateMnemonicWords15 = 0x05 // 15 words (160 bits entropy)
	P1GenerateMnemonicWords18 = 0x06 // 18 words (192 bits entropy)
	P1GenerateMnemonicWords21 = 0x07 // 21 words (224 bits entropy)
	P1GenerateMnemonicWords24 = 0x08 // 24 words (256 bits entropy)
)

// ============================================================================
// Capability flags
// ============================================================================

// Capability flags are defined in types/application_info.go to avoid
// circular imports (types package is imported by keycard package).
// See types.Capability for the type and constants.

// ============================================================================
// App status flags
// ============================================================================

// App status flag bits.
const (
	AppStatusInitialized = 0x10 // App is initialized
	AppStatusLEEMode     = 0x20 // App is in LEE mode
)

// ============================================================================
// Other constants
// ============================================================================

// NDEFMaxChunkSize is the maximum NDEF chunk size for storage (220 bytes).
const NDEFMaxChunkSize = 220

// PairingMaxClientCount is the maximum number of pairing slots on the card.
const PairingMaxClientCount = 5

// DefaultCAPublicKey is the default Status CA public key (compressed secp256k1, 33 bytes).
var DefaultCAPublicKey = [33]byte{
	0x02,
	0x9a, 0xb9, 0x9e, 0xe1, 0xe7, 0xa7, 0x1b,
	0xdf, 0x45, 0xb3, 0xf9, 0xc5, 0x8c, 0x99,
	0x86, 0x6f, 0xf1, 0x29, 0x4d, 0x2c, 0x1e,
	0x30, 0x4e, 0x22, 0x8a, 0x86, 0xe1, 0x0c,
	0x33, 0x43, 0x50, 0x1c,
}

// PairingPasswordSalt is the salt used for deriving the pairing secret.
const PairingPasswordSalt = "Keycard Pairing Password Salt"

// MnemonicSeedPrefix is the BIP39 mnemonic seed derivation prefix.
const MnemonicSeedPrefix = "mnemonic"

// MnemonicPBKDF2Iterations is the number of PBKDF2 iterations for mnemonic seed derivation.
const MnemonicPBKDF2Iterations = 2048

// BIP32HMACKey is the HMAC key used for BIP32 master key derivation.
const BIP32HMACKey = "Bitcoin seed"

// SwNoAvailablePairingSlots is the status word returned when no pairing slots are available.
const SwNoAvailablePairingSlots = 0x6A84

// ============================================================================
// Secure Channel version
// ============================================================================

// SecureChannelVersion identifies which secure channel protocol is in use.
type SecureChannelVersion int

const (
	VersionV1 SecureChannelVersion = iota
	VersionV2
)

// ============================================================================
// Deprecated aliases (kept for backward compatibility)
// ============================================================================

// Deprecated: Use globalplatform.ClaGp.
const ClaGp = globalplatform.ClaGp
