package globalplatform

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform/crypto"
)

// Session is the state established with a Security Domain by INITIALIZE UPDATE: the
// session keys, the challenges of both parties and the protection the card accepted.
type Session struct {
	protocol      SCPVersion
	version       byte
	level         SecurityLevel
	macLen        int
	iParameter    byte
	hostChallenge []byte
	cardChallenge []byte
	hostCrypto    []byte
	senc          []byte
	smac          []byte
	srmac         []byte
	dek           []byte
}

var errBadCryptogram = errors.New("bad card cryptogram")

// NewSession validates the card cryptogram returned in an INITIALIZE UPDATE response and
// returns the session to use for EXTERNAL AUTHENTICATE and for wrapping commands.
// hostChallenge must be the value sent in INITIALIZE UPDATE.
func NewSession(keySet KeySet, resp *apdu.Response, hostChallenge []byte, level SecurityLevel) (*Session, error) {
	if resp.Sw == SwSecurityConditionNotSatisfied {
		return nil, apdu.NewErrBadResponse(resp.Sw, "security condition not satisfied")
	}

	if resp.Sw == SwAuthenticationMethodBlocked {
		return nil, apdu.NewErrBadResponse(resp.Sw, "authentication method blocked")
	}

	if err := keySet.Validate(); err != nil {
		return nil, err
	}

	if len(resp.Data) < 13 {
		return nil, apdu.NewErrBadResponse(resp.Sw, fmt.Sprintf("bad data length, expected at least 13, got %d", len(resp.Data)))
	}

	switch scp := resp.Data[11]; scp {
	case byte(SCPVersion02):
		return newSCP02Session(keySet, resp.Data, hostChallenge, level)
	case byte(SCPVersion03):
		return newSCP03Session(keySet, resp.Data, hostChallenge, level)
	default:
		return nil, fmt.Errorf("scp version %d not supported", scp)
	}
}

func newSCP02Session(keySet KeySet, data, hostChallenge []byte, level SecurityLevel) (*Session, error) {
	if len(data) != 28 {
		return nil, apdu.NewErrBadResponse(SwOK, fmt.Sprintf("bad data length, expected 28, got %d", len(data)))
	}

	if level&^levelCMAC != 0 {
		return nil, fmt.Errorf("scp02 sessions support only the mac security level, got 0x%02x", level)
	}

	// The 8 bytes at offset 12 are the key sequence counter followed by the random part
	// of the card challenge; both are covered by the card cryptogram.
	cardChallenge := data[12:20]
	cardCryptogram := data[20:28]
	seq := data[12:14]

	sessionEncKey, err := crypto.DeriveKey(keySet.Enc(), seq, crypto.DerivationPurposeEnc)
	if err != nil {
		return nil, err
	}

	sessionMacKey, err := crypto.DeriveKey(keySet.Mac(), seq, crypto.DerivationPurposeMac)
	if err != nil {
		return nil, err
	}

	verified, err := crypto.VerifyCryptogram(sessionEncKey, hostChallenge, cardChallenge, cardCryptogram)
	if err != nil {
		return nil, err
	}

	if !verified {
		return nil, errBadCryptogram
	}

	hostCrypto, err := calculateHostCryptogram(sessionEncKey, cardChallenge, hostChallenge)
	if err != nil {
		return nil, err
	}

	return &Session{
		protocol:      SCPVersion02,
		level:         level,
		macLen:        scp02MACLength,
		hostChallenge: hostChallenge,
		cardChallenge: cardChallenge,
		hostCrypto:    hostCrypto,
		senc:          sessionEncKey,
		smac:          sessionMacKey,
		dek:           keySet.Dek(),
	}, nil
}

func newSCP03Session(keySet KeySet, data, hostChallenge []byte, level SecurityLevel) (*Session, error) {
	iParameter := data[12]
	macLen := macSize(iParameter)

	// key diversification data (10) | key information (3) | card challenge | card
	// cryptogram, plus the sequence counter of a card configured for pseudo-random
	// challenges.
	expected := 13 + 2*macLen
	if iParameter&iParameterPseudoRandom != 0 {
		expected += 3
	}

	if len(data) != expected {
		return nil, apdu.NewErrBadResponse(SwOK, fmt.Sprintf("bad data length, expected %d, got %d", expected, len(data)))
	}

	if len(hostChallenge) != macLen {
		return nil, fmt.Errorf("host challenge must be %d bytes for the mode reported by the card, got %d", macLen, len(hostChallenge))
	}

	if !supportsResponses(iParameter, level) {
		return nil, fmt.Errorf("card does not support the response protection of security level 0x%02x (i parameter 0x%02x)", level, iParameter)
	}

	context := make([]byte, 0, 2*macLen)
	context = append(context, hostChallenge...)
	context = append(context, data[13:13+macLen]...)

	bits := len(keySet.Enc()) * 8
	cryptogramBits := macLen * 8

	senc, err := crypto.DeriveSCP03Key(keySet.Enc(), crypto.DerivationConstantSENC, context, bits)
	if err != nil {
		return nil, err
	}

	smac, err := crypto.DeriveSCP03Key(keySet.Mac(), crypto.DerivationConstantSMAC, context, bits)
	if err != nil {
		return nil, err
	}

	srmac, err := crypto.DeriveSCP03Key(keySet.Mac(), crypto.DerivationConstantSRMAC, context, bits)
	if err != nil {
		return nil, err
	}

	cardCryptogram, err := crypto.DeriveSCP03Key(smac, crypto.DerivationConstantCardCryptogram, context, cryptogramBits)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(cardCryptogram, data[13+macLen:13+2*macLen]) {
		return nil, errBadCryptogram
	}

	hostCrypto, err := crypto.DeriveSCP03Key(smac, crypto.DerivationConstantHostCryptogram, context, cryptogramBits)
	if err != nil {
		return nil, err
	}

	return &Session{
		protocol:      SCPVersion03,
		version:       data[10],
		level:         level,
		macLen:        macLen,
		iParameter:    iParameter,
		hostChallenge: hostChallenge,
		cardChallenge: data[13 : 13+macLen],
		hostCrypto:    hostCrypto,
		senc:          senc,
		smac:          smac,
		srmac:         srmac,
		dek:           keySet.Dek(),
	}, nil
}

// Protocol returns the Secure Channel Protocol negotiated with the card.
func (s *Session) Protocol() SCPVersion {
	return s.protocol
}

// KeyVersion returns the Key Version Number of the key set the card used.
func (s *Session) KeyVersion() byte {
	return s.version
}

// SecurityLevel returns the secure messaging level of the session.
func (s *Session) SecurityLevel() SecurityLevel {
	return s.level
}

// IParameter returns the SCP03 "i" parameter reported by the card, 0 for SCP02 sessions.
func (s *Session) IParameter() byte {
	return s.iParameter
}

// Keys returns the keys of a SCP02 session, nil for other protocols.
func (s *Session) Keys() *SCP02Keys {
	if s.protocol != SCPVersion02 {
		return nil
	}

	return NewSCP02Keys(s.senc, s.smac)
}

// HostChallenge returns the challenge sent to the card in INITIALIZE UPDATE.
func (s *Session) HostChallenge() []byte {
	return s.hostChallenge
}

// CardChallenge returns the challenge received from the card in INITIALIZE UPDATE.
func (s *Session) CardChallenge() []byte {
	return s.cardChallenge
}

// ExternalAuthenticate returns the command authenticating the host to the card and
// setting the security level of the session.
func (s *Session) ExternalAuthenticate() *apdu.Command {
	if s.protocol == SCPVersion03 {
		return NewCommandExternalAuthenticateSCP03(s.level, s.hostCrypto)
	}

	return NewCommandExternalAuthenticateSCP02(s.hostCrypto)
}

// newWrapper returns the secure messaging wrapper of the session.
func (s *Session) newWrapper() (secureMessagingWrapper, error) {
	if s.protocol == SCPVersion03 {
		return NewSCP03Wrapper(s.senc, s.smac, s.srmac, s.level, s.macLen)
	}

	return NewSCP02Wrapper(s.smac), nil
}
