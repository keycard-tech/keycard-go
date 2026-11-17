package globalplatform

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/identifiers"
	"github.com/keycard-tech/keycard-go/v4/types"
)

var ErrSecureChannelNotOpen = errors.New("secure channel not open")

type LoadingCallback = func(loadingBlock, totalBlocks int)

type CommandSet struct {
	c             types.Channel
	sc            *SecureChannel
	session       *Session
	keySets       []KeySet
	securityLevel SecurityLevel
}

// Option configures how a CommandSet opens its secure channel.
type Option func(*CommandSet)

// WithKeySets sets the key sets to offer the card when opening a secure channel, tried
// in order. The card may block a Security Domain after repeated authentication failures,
// so keep the list as short as the cards allow.
func WithKeySets(keySets ...KeySet) Option {
	return func(cs *CommandSet) {
		cs.keySets = keySets
	}
}

// WithSecurityLevel sets the secure messaging level of SCP03 sessions, LevelCMAC by
// default. Levels including R-MAC or R-ENCRYPTION require a card advertising them.
func WithSecurityLevel(level SecurityLevel) Option {
	return func(cs *CommandSet) {
		cs.securityLevel = level
	}
}

// NewCommandSet returns a CommandSet sending on channel c, which tries the public
// development key sets of DefaultKeySets unless WithKeySets says otherwise.
func NewCommandSet(c types.Channel, options ...Option) *CommandSet {
	cs := &CommandSet{
		c:             c,
		keySets:       DefaultKeySets(),
		securityLevel: DefaultSecurityLevel,
	}

	for _, option := range options {
		option(cs)
	}

	return cs
}

func (cs *CommandSet) Select() error {
	return cs.SelectAID(nil)
}

func (cs *CommandSet) SelectAID(aid []byte) error {
	cmd := NewCommandSelect(aid)
	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)

	return apdu.CheckOK(resp, err)
}

// OpenSecureChannel negotiates a secure channel with the Security Domain: it sends an
// INITIALIZE UPDATE per key set until one of them yields a valid card cryptogram, then
// authenticates the host. The protocol is the one the card reports, so SCP02 and SCP03
// cards are handled by the same call.
func (cs *CommandSet) OpenSecureChannel() error {
	var lastErr error

	for _, keySet := range cs.keySets {
		session, err := cs.negotiate(keySet)
		if err != nil {
			if !isKeySetError(err) {
				return err
			}

			logger.Debug("key set rejected", "scp", keySet.Protocol(), "version", keySet.Version(), "error", err)
			lastErr = err

			continue
		}

		cs.session = session

		break
	}

	if cs.session == nil {
		if lastErr == nil {
			return errors.New("no key set configured")
		}

		return fmt.Errorf("no key set accepted by the card: %w", lastErr)
	}

	return cs.externalAuthenticate()
}

// negotiate sends an INITIALIZE UPDATE and validates the returned card cryptogram,
// leaving a secure channel ready to authenticate the host when the keys match.
func (cs *CommandSet) negotiate(keySet KeySet) (*Session, error) {
	// A SCP03 card configured for S16 mode rejects an 8 byte host challenge with '6700'.
	challengeLengths := []int{8}
	if keySet.Protocol() == SCPVersion03 {
		challengeLengths = append(challengeLengths, 16)
	}

	var lastErr error

	for _, length := range challengeLengths {
		hostChallenge, err := generateHostChallenge(length)
		if err != nil {
			return nil, err
		}

		cmd := NewCommandInitializeUpdate(hostChallenge, keySet.Version())
		resp, err := cs.c.Send(cmd)
		if err != nil {
			return nil, err
		}

		if resp.Sw == SwWrongLength {
			lastErr = apdu.NewErrBadResponse(resp.Sw, "host challenge length rejected")

			continue
		}

		if err = apdu.CheckOK(resp, err); err != nil {
			return nil, err
		}

		session, err := NewSession(keySet, resp, hostChallenge, cs.securityLevel)
		if err != nil {
			if !isKeySetError(err) {
				return nil, err
			}

			// The card accepted the challenge, so asking again with another length would
			// only burn authentication attempts on this Security Domain.
			lastErr = err

			break
		}

		if cs.sc, err = NewSecureChannel(session, cs.c); err != nil {
			return nil, err
		}

		logger.Debug("secure channel negotiated", "scp", session.Protocol(), "version", session.KeyVersion())

		return session, nil
	}

	return nil, lastErr
}

func (cs *CommandSet) DeleteKeycardInstancesAndPackage() error {
	if cs.sc == nil {
		return ErrSecureChannelNotOpen
	}

	return cs.DeleteObjectAndRelatedObject(identifiers.PackageAID)
}

func (cs *CommandSet) DeleteObject(aid []byte) error {
	return cs.Delete(aid, P2DeleteObject)
}

func (cs *CommandSet) DeleteObjectAndRelatedObject(aid []byte) error {
	return cs.Delete(aid, P2DeleteObjectAndRelatedObject)
}

func (cs *CommandSet) Delete(aid []byte, p2 uint8) error {
	cmd := NewCommandDelete(aid, p2)
	resp, err := cs.sc.Send(cmd)
	return apdu.CheckOK(resp, err, SwOK, SwReferencedDataNotFound)
}

func (cs *CommandSet) LoadKeycardPackage(capFile *os.File, callback LoadingCallback) error {
	return cs.LoadPackage(capFile, identifiers.PackageAID, callback)
}

func (cs *CommandSet) LoadPackage(capFile *os.File, pkgAID []byte, callback LoadingCallback) error {
	if cs.sc == nil {
		return ErrSecureChannelNotOpen
	}

	preLoad := NewCommandInstallForLoad(pkgAID, []byte{})
	resp, err := cs.sc.Send(preLoad)
	if err = apdu.CheckOK(resp, err); err != nil {
		return err
	}

	load, err := NewLoadCommandStream(capFile, cs.sc.MaxCommandData())
	if err != nil {
		return err
	}

	for load.Next() {
		cmd := load.GetCommand()
		callback(int(load.Index()), load.BlocksCount())
		resp, err = cs.sc.Send(cmd)
		if err = apdu.CheckOK(resp, err); err != nil {
			return err
		}
	}

	return nil
}

func (cs *CommandSet) InstallNDEFApplet(ndefRecord []byte) error {
	return cs.InstallForInstall(
		identifiers.PackageAID,
		identifiers.NdefAID,
		identifiers.NdefInstanceAID,
		ndefRecord)
}

func (cs *CommandSet) InstallKeycardApplet() error {
	instanceAID, err := identifiers.KeycardInstanceAID(identifiers.KeycardDefaultInstanceIndex)
	if err != nil {
		return err
	}

	return cs.InstallForInstall(
		identifiers.PackageAID,
		identifiers.KeycardAID,
		instanceAID,
		[]byte{})
}

func (cs *CommandSet) InstallCashApplet() error {
	return cs.InstallForInstall(
		identifiers.PackageAID,
		identifiers.CashAID,
		identifiers.CashInstanceAID,
		[]byte{})
}

func (cs *CommandSet) InstallIdentApplet() error {
	return cs.InstallForInstall(
		identifiers.PackageAID,
		identifiers.IdentAID,
		identifiers.IdentInstanceAID,
		[]byte{})
}

func (cs *CommandSet) InstallForInstall(packageAID, appletAID, instanceAID, params []byte) error {
	cmd := NewCommandInstallForInstall(packageAID, appletAID, instanceAID, params)
	resp, err := cs.sc.Send(cmd)
	return apdu.CheckOK(resp, err)
}

func (cs *CommandSet) GetStatus() (*types.CardStatus, error) {
	cmd := NewCommandGetStatus([]byte{}, P1GetStatusIssuerSecurityDomain)
	resp, err := cs.sc.Send(cmd)
	if err = apdu.CheckOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseCardStatus(resp.Data)
}

func (cs *CommandSet) Channel() types.Channel {
	return cs.c
}

func (cs *CommandSet) SecureChannel() *SecureChannel {
	return cs.sc
}

// Session returns the session of the open secure channel, nil when none is open.
func (cs *CommandSet) Session() *Session {
	return cs.session
}

func (cs *CommandSet) externalAuthenticate() error {
	if cs.session == nil {
		return errors.New("session must be initialized using initializeUpdate")
	}

	resp, err := cs.sc.SendAuthenticate(cs.session.ExternalAuthenticate())
	if err != nil {
		return err
	}

	return apdu.CheckOK(resp, err)
}

// isKeySetError reports whether an error means the card does not use this key set, so
// that the next one can be offered.
func isKeySetError(err error) bool {
	var badResponse *apdu.ErrBadResponse
	if errors.As(err, &badResponse) {
		return badResponse.Sw == SwReferencedDataNotFound
	}

	return errors.Is(err, errBadCryptogram)
}

func generateHostChallenge(length int) ([]byte, error) {
	c := make([]byte, length)
	_, err := rand.Read(c)

	return c, err
}
