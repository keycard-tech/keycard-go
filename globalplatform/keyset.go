package globalplatform

import (
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/identifiers"
)

// SCPVersion is the Secure Channel Protocol a key set is configured for on the card.
type SCPVersion uint8

const (
	SCPVersion02 SCPVersion = 2
	SCPVersion03 SCPVersion = 3
)

// SecurityLevel is the level of secure messaging applied to the commands of a session.
// It is the value of the reference control parameter P1 of EXTERNAL AUTHENTICATE and is
// only meaningful for SCP03, where SCP02 sessions always carry a MAC and never encrypt.
type SecurityLevel uint8

// Security level bits (GP Card Spec v2.3 Amendment D, Table 7-6).
const (
	levelCMAC SecurityLevel = 0x01
	levelCDEC SecurityLevel = 0x02
	levelRMAC SecurityLevel = 0x10
	levelRENC SecurityLevel = 0x20
)

const (
	// LevelNone opens a session without secure messaging on the following commands.
	LevelNone SecurityLevel = 0x00
	// LevelCMAC authenticates commands, the level used by SCP02 sessions.
	LevelCMAC SecurityLevel = levelCMAC
	// LevelCDECMAC authenticates and encrypts commands.
	LevelCDECMAC SecurityLevel = levelCMAC | levelCDEC
	// LevelCMACRMAC authenticates commands and responses.
	LevelCMACRMAC SecurityLevel = levelCMAC | levelRMAC
	// LevelCDECMACRMAC authenticates commands and responses, and encrypts commands.
	LevelCDECMACRMAC SecurityLevel = levelCMAC | levelCDEC | levelRMAC
	// LevelFull authenticates and encrypts in both directions.
	LevelFull SecurityLevel = levelCMAC | levelCDEC | levelRMAC | levelRENC
)

// DefaultSecurityLevel is the level used when none is configured: commands carry a MAC
// and responses are unprotected, matching what an SCP02 session does.
const DefaultSecurityLevel = LevelCMAC

// Bits of the SCP03 "i" parameter reported by the card, Table 5-1 of Amendment D. It
// says nothing about C-MAC or C-DECRYPTION: those are chosen by the host in EXTERNAL
// AUTHENTICATE, the card only reports the mode of the challenge and what it can do to
// responses.
const (
	iParameterS16          = 0x01
	iParameterPseudoRandom = 0x10
	iParameterRMACSupport  = 0x20
	iParameterRENCSupport  = 0x40
)

// macSize returns the length in bytes of the C-MAC and R-MAC of a SCP03 session.
// Mode S16 (16 bytes) is indicated by the least significant bit of the card "i" parameter.
func macSize(iParameter byte) int {
	if iParameter&iParameterS16 != 0 {
		return 16
	}

	return 8
}

// supportsResponses reports whether the card "i" parameter advertises the response
// protection requested by the level.
func supportsResponses(iParameter byte, level SecurityLevel) bool {
	if level&levelRMAC == 0 {
		return true
	}

	return iParameter&iParameterRMACSupport != 0 && (level&levelRENC == 0 || iParameter&iParameterRENCSupport != 0)
}

// KeySet is a set of static Secure Channel keys stored in a Security Domain of a card.
type KeySet struct {
	protocol SCPVersion
	version  byte
	enc      []byte
	mac      []byte
	dek      []byte
}

// NewSCP02KeySet returns a SCP02 key set where the same static key protects
// confidentiality and integrity, the configuration used by the Keycard development cards.
func NewSCP02KeySet(key []byte) KeySet {
	return NewSCP02KeySetSplit(key, key)
}

// NewSCP02KeySetSplit returns a SCP02 key set with separate static ENC and MAC keys.
func NewSCP02KeySetSplit(enc, mac []byte) KeySet {
	return KeySet{protocol: SCPVersion02, version: 0, enc: enc, mac: mac}
}

// NewSCP03KeySet returns a SCP03 key set. The version is the Key Version Number selecting
// the key set on the card; use 0 to let the card pick its first available key set.
// The dek is optional: it is only needed to wrap key material for commands that import keys.
func NewSCP03KeySet(version byte, enc, mac, dek []byte) KeySet {
	return KeySet{protocol: SCPVersion03, version: version, enc: enc, mac: mac, dek: dek}
}

// DefaultKeySets returns the public development key sets to try, in order.
func DefaultKeySets() []KeySet {
	return []KeySet{
		NewSCP02KeySet(identifiers.KeycardDevelopmentKey),
		NewSCP02KeySet(identifiers.GlobalPlatformDefaultKey),
		NewSCP03KeySet(0, identifiers.GlobalPlatformDefaultKey, identifiers.GlobalPlatformDefaultKey, identifiers.GlobalPlatformDefaultKey),
	}
}

// Protocol returns the Secure Channel Protocol the key set is configured for.
func (k KeySet) Protocol() SCPVersion {
	return k.protocol
}

// Version returns the Key Version Number of the key set, 0 for SCP02 key sets.
func (k KeySet) Version() byte {
	return k.version
}

// Enc returns the static confidentiality key.
func (k KeySet) Enc() []byte {
	return k.enc
}

// Mac returns the static integrity key.
func (k KeySet) Mac() []byte {
	return k.mac
}

// Dek returns the static key encryption key, nil when not available.
func (k KeySet) Dek() []byte {
	return k.dek
}

// Validate checks that the key set carries key material usable with its protocol.
func (k KeySet) Validate() error {
	switch k.protocol {
	case SCPVersion02:
		if !is3DESKey(k.enc) || !is3DESKey(k.mac) {
			return fmt.Errorf("scp02 keys must be 16 or 24 bytes, got enc=%d mac=%d", len(k.enc), len(k.mac))
		}
	case SCPVersion03:
		if !isAESKey(k.enc) || !isAESKey(k.mac) {
			return fmt.Errorf("scp03 keys must be 16, 24 or 32 bytes, got enc=%d mac=%d", len(k.enc), len(k.mac))
		}
		if len(k.enc) != len(k.mac) {
			return fmt.Errorf("scp03 enc and mac keys must have the same length, got %d and %d", len(k.enc), len(k.mac))
		}
		if len(k.dek) != 0 && len(k.dek) != len(k.enc) {
			return fmt.Errorf("scp03 dek key must have the same length as the other keys, got %d", len(k.dek))
		}
	default:
		return fmt.Errorf("unsupported scp version %d", k.protocol)
	}

	return nil
}

func is3DESKey(key []byte) bool {
	return len(key) == 16 || len(key) == 24
}

func isAESKey(key []byte) bool {
	return len(key) == 16 || len(key) == 24 || len(key) == 32
}
