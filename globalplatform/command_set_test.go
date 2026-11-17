package globalplatform

import (
	"bytes"
	"testing"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform/crypto"
	"github.com/keycard-tech/keycard-go/v4/hexutils"
	"github.com/keycard-tech/keycard-go/v4/identifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The card challenge of the JCOP4 transcript in PeculiarVentures/scp.
const jcopCardChallenge = "734ECDCA19E446A3"

// fakeCard answers an install session like a Security Domain holding the given static
// keys. The card cryptogram is derived from the challenge the host really sent, with the
// crypto package, which has its own known-answer tests.
type fakeCard struct {
	keySet     KeySet
	iParameter byte
	// unknownKeyVersions makes the card reject any INITIALIZE UPDATE naming a key version
	// it does not hold.
	unknownKeyVersions bool
	cardChallenge      []byte
	commands           []*apdu.Command
}

func (c *fakeCard) Send(cmd *apdu.Command) (*apdu.Response, error) {
	raw, err := cmd.Serialize()
	if err != nil {
		return nil, err
	}

	snapshot, err := apdu.ParseCommand(raw)
	if err != nil {
		return nil, err
	}

	c.commands = append(c.commands, snapshot)

	switch cmd.Ins {
	case InsInitializeUpdate:
		return c.initializeUpdate(cmd.P1, cmd.Data)
	case InsSelect:
		return okResponse(hexutils.MustHexToBytes("6F0A8408A000000804000100"))
	}

	return okResponse(nil)
}

func (c *fakeCard) initializeUpdate(keyVersion byte, hostChallenge []byte) (*apdu.Response, error) {
	if c.unknownKeyVersions && keyVersion != c.keySet.Version() {
		return apdu.ParseResponse(hexutils.MustHexToBytes("6A88"))
	}

	if c.keySet.Protocol() == SCPVersion02 {
		return c.initializeUpdateSCP02(hostChallenge)
	}

	macLen := macSize(c.iParameter)
	if len(hostChallenge) != macLen {
		return apdu.ParseResponse(hexutils.MustHexToBytes("6700"))
	}

	cardCryptogram, err := c.scp03CardCryptogram(hostChallenge, macLen)
	if err != nil {
		return nil, err
	}

	data := hexutils.MustHexToBytes("A0000001510000000000")
	data = append(data, c.keySet.Version(), byte(SCPVersion03), c.iParameter)
	data = append(data, c.cardChallenge...)
	data = append(data, cardCryptogram...)

	if c.iParameter&iParameterPseudoRandom != 0 {
		data = append(data, 0x00, 0x00, 0x01)
	}

	return okResponse(data)
}

func (c *fakeCard) scp03CardCryptogram(hostChallenge []byte, macLen int) ([]byte, error) {
	context := make([]byte, 0, len(hostChallenge)+len(c.cardChallenge))
	context = append(context, hostChallenge...)
	context = append(context, c.cardChallenge...)

	smac, err := crypto.DeriveSCP03Key(c.keySet.Mac(), crypto.DerivationConstantSMAC, context, len(c.keySet.Mac())*8)
	if err != nil {
		return nil, err
	}

	return crypto.DeriveSCP03Key(smac, crypto.DerivationConstantCardCryptogram, context, macLen*8)
}

func (c *fakeCard) initializeUpdateSCP02(hostChallenge []byte) (*apdu.Response, error) {
	if len(hostChallenge) != 8 {
		return apdu.ParseResponse(hexutils.MustHexToBytes("6700"))
	}

	// JCOP puts the sequence counter where the challenge starts, so it is covered by the
	// card cryptogram.
	sessionEnc, err := crypto.DeriveKey(c.keySet.Enc(), c.cardChallenge[:2], crypto.DerivationPurposeEnc)
	if err != nil {
		return nil, err
	}

	cardCryptogram, err := crypto.Mac3DES(sessionEnc, crypto.AppendDESPadding(append(append([]byte{}, hostChallenge...), c.cardChallenge...)), crypto.NullBytes8)
	if err != nil {
		return nil, err
	}

	// A SCP02 response has no "i" byte: the key information is followed directly by the
	// 8 byte challenge field, whose first two bytes are the sequence counter.
	data := hexutils.MustHexToBytes("A0000001510000000000")
	data = append(data, c.keySet.Version(), byte(SCPVersion02))
	data = append(data, c.cardChallenge...)
	data = append(data, cardCryptogram...)

	return okResponse(data)
}

func okResponse(data []byte) (*apdu.Response, error) {
	raw := make([]byte, 0, len(data)+2)
	raw = append(raw, data...)
	raw = append(raw, 0x90, 0x00)

	return apdu.ParseResponse(raw)
}

func (c *fakeCard) commandNames() []string {
	names := make([]string, 0, len(c.commands))
	for _, cmd := range c.commands {
		names = append(names, hexutils.BytesToHex([]byte{cmd.Cla, cmd.Ins}))
	}

	return names
}

func scp03Card(keyVersion byte, iParameter byte, challenge string) *fakeCard {
	key := identifiers.GlobalPlatformDefaultKey

	return &fakeCard{
		keySet:        NewSCP03KeySet(keyVersion, key, key, key),
		iParameter:    iParameter,
		cardChallenge: hexutils.MustHexToBytes(challenge),
	}
}

func TestCommandSet_SCP03(t *testing.T) {
	// A card in S16 mode refuses the 8 byte challenge of a first attempt with '6700'.
	tests := []struct {
		name       string
		iParameter byte
		level      SecurityLevel
		challenge  string
		retries    int
	}{
		{"S8 mac", 0x10, LevelCMAC, jcopCardChallenge, 0},
		{"S8 encrypted", 0x10, LevelCDECMAC, jcopCardChallenge, 0},
		{"S16 mac", 0x11, LevelCMAC, "0617A2C34D50B562F7DECFC3DBF58A64", 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			card := scp03Card(0x30, test.iParameter, test.challenge)

			cmdSet := NewCommandSet(card, WithSecurityLevel(test.level), WithKeySets(card.keySet))
			require.NoError(t, cmdSet.Select())
			require.NoError(t, cmdSet.OpenSecureChannel())
			require.NoError(t, cmdSet.Delete(identifiers.KeycardAID, P2DeleteObject))

			require.Len(t, card.commands, 4+test.retries, "%v", card.commandNames())

			update := card.commands[1+test.retries]
			assert.Equal(t, byte(InsInitializeUpdate), update.Ins)
			assert.Equal(t, byte(0x30), update.P1, "the key set version must be requested by name")
			assert.Len(t, update.Data, len(card.cardChallenge))

			authenticate := card.commands[2+test.retries]
			assert.Equal(t, byte(InsExternalAuthenticate), authenticate.Ins)
			assert.Equal(t, byte(test.level), authenticate.P1)
			assert.Equal(t, 2*len(card.cardChallenge), len(authenticate.Data), "host cryptogram and C-MAC")

			deletion := card.commands[3+test.retries]
			assert.Equal(t, byte(0x04), deletion.Cla&0x04, "class byte must indicate secure messaging")

			macLen := macSize(test.iParameter)
			plain := append([]byte{0x4f, byte(len(identifiers.KeycardAID))}, identifiers.KeycardAID...)

			if test.level&levelCDEC != 0 {
				assert.Equal(t, 0, (len(deletion.Data)-macLen)%crypto.AESBlockSize)
				assert.NotEqual(t, plain, deletion.Data[:len(plain)], "the AID must be encrypted")
			} else {
				assert.Equal(t, plain, deletion.Data[:len(plain)])
				assert.Equal(t, len(plain)+macLen, len(deletion.Data))
			}
		})
	}
}

// The key sets are tried in order, so a card that only knows a version further down the
// list still gets a session.
func TestCommandSet_KeySetFallback(t *testing.T) {
	card := scp03Card(0x02, 0x10, jcopCardChallenge)
	card.unknownKeyVersions = true

	other := NewSCP03KeySet(0xFF, make([]byte, 16), make([]byte, 16), make([]byte, 16))

	cmdSet := NewCommandSet(card, WithKeySets(other, card.keySet))
	require.NoError(t, cmdSet.Select())
	require.NoError(t, cmdSet.OpenSecureChannel())

	require.Len(t, card.commands, 4, "%v", card.commandNames())
	assert.Equal(t, byte(0xFF), card.commands[1].P1)
	assert.Equal(t, byte(0x02), card.commands[2].P1)
	assert.Equal(t, byte(InsExternalAuthenticate), card.commands[3].Ins)
	assert.Equal(t, byte(0x02), cmdSet.Session().KeyVersion())
}

func TestCommandSet_NoKeySets(t *testing.T) {
	card := &fakeCard{}
	cmdSet := NewCommandSet(card, WithKeySets())

	assert.Error(t, cmdSet.OpenSecureChannel())
	assert.Empty(t, card.commands, "no key set means no INITIALIZE UPDATE")
}

// A card that cannot provide the requested protection is not retried with the other key
// sets.
func TestCommandSet_LevelNotSupported(t *testing.T) {
	card := scp03Card(0x30, 0x10, jcopCardChallenge) // the "i" parameter has no R-MAC bit

	cmdSet := NewCommandSet(card, WithKeySets(card.keySet, card.keySet), WithSecurityLevel(LevelCMACRMAC))
	require.NoError(t, cmdSet.Select())

	assert.Error(t, cmdSet.OpenSecureChannel())
	// Only the SELECT and the INITIALIZE UPDATE that told us about the "i" parameter.
	assert.Len(t, card.commands, 2, "a card that cannot do R-MAC is not probed again")
}

func TestCommandSet_SCP02(t *testing.T) {
	card := &fakeCard{
		keySet:        NewSCP02KeySet(identifiers.GlobalPlatformDefaultKey),
		cardChallenge: hexutils.MustHexToBytes(jcopCardChallenge),
	}

	cmdSet := NewCommandSet(card, WithKeySets(card.keySet))
	require.NoError(t, cmdSet.Select())
	require.NoError(t, cmdSet.OpenSecureChannel())
	require.NoError(t, cmdSet.Delete(identifiers.KeycardAID, P2DeleteObject))

	require.Len(t, card.commands, 4, "%v", card.commandNames())
	assert.Equal(t, SCPVersion02, cmdSet.Session().Protocol())
	assert.Equal(t, byte(0), card.commands[1].P1, "SCP02 cards are asked to pick the key set")
	assert.Equal(t, byte(InsExternalAuthenticate), card.commands[2].Ins)
	assert.Equal(t, 16, len(card.commands[2].Data))

	deletion := card.commands[3]
	assert.Equal(t, byte(0x04), deletion.Cla&0x04)
	assert.Equal(t, scp02MACLength, len(deletion.Data)-len(identifiers.KeycardAID)-2, "the MAC is appended to the plain data")
}

// The public development key of the Keycard installers is offered before the
// GlobalPlatform one, so a card left at the Keycard defaults needs no configuration.
// The load blocks are sized for the protection of the session, not for a bare APDU.
func TestCommandSet_LoadBlockSize(t *testing.T) {
	tests := []struct {
		name       string
		iParameter byte
		level      SecurityLevel
		maxData    int
		challenge  string
	}{
		{"mac only", 0x10, LevelCMAC, 247, jcopCardChallenge},
		{"encrypted", 0x10, LevelCDECMAC, 239, jcopCardChallenge},
		{"encrypted s16", 0x11, LevelCDECMAC, 223, "0617A2C34D50B562F7DECFC3DBF58A64"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			card := scp03Card(0x30, test.iParameter, test.challenge)

			cmdSet := NewCommandSet(card, WithKeySets(card.keySet), WithSecurityLevel(test.level))
			require.NoError(t, cmdSet.Select())
			require.NoError(t, cmdSet.OpenSecureChannel())

			assert.Equal(t, test.maxData, cmdSet.SecureChannel().MaxCommandData())

			file := capFile(t, map[string][]byte{"Header": bytes.Repeat([]byte{0xAB}, 600)})
			require.NoError(t, cmdSet.LoadPackage(file, identifiers.PackageAID, func(_, _ int) {}))

			var loads int

			for _, cmd := range card.commands {
				if cmd.Ins != InsLoad {
					continue
				}

				loads++
				assert.LessOrEqual(t, len(cmd.Data), 255, "load block %d does not fit the apdu", loads)
			}

			assert.Equal(t, 3, loads)
		})
	}
}

func TestCommandSet_DefaultKeySets(t *testing.T) {
	card := &fakeCard{
		keySet:        NewSCP02KeySet(identifiers.KeycardDevelopmentKey),
		cardChallenge: hexutils.MustHexToBytes(jcopCardChallenge),
	}

	cmdSet := NewCommandSet(card)
	require.NoError(t, cmdSet.Select())
	require.NoError(t, cmdSet.OpenSecureChannel())

	assert.Equal(t, SCPVersion02, cmdSet.Session().Protocol())
	assert.Len(t, card.commands, 3, "%v", card.commandNames())
}

func TestCommandSet_DefaultSecurityLevel(t *testing.T) {
	card := scp03Card(0x30, 0x10, jcopCardChallenge)

	cmdSet := NewCommandSet(card, WithKeySets(card.keySet))
	require.NoError(t, cmdSet.Select())
	require.NoError(t, cmdSet.OpenSecureChannel())

	assert.Equal(t, DefaultSecurityLevel, cmdSet.Session().SecurityLevel())
	assert.Equal(t, byte(DefaultSecurityLevel), card.commands[2].P1)
}

// A card answering '6700' to an 8 byte challenge is in S16 mode and gets a retry.
func TestCommandSet_SCP03_S16Retry(t *testing.T) {
	card := scp03Card(0x30, 0x11, "0617A2C34D50B562F7DECFC3DBF58A64")

	cmdSet := NewCommandSet(card, WithKeySets(card.keySet))
	require.NoError(t, cmdSet.Select())
	require.NoError(t, cmdSet.OpenSecureChannel())

	require.Len(t, card.commands, 4, "%v", card.commandNames())
	assert.Len(t, card.commands[1].Data, 8, "the first attempt uses an 8 byte challenge")
	assert.Len(t, card.commands[2].Data, 16)
	assert.Equal(t, byte(InsExternalAuthenticate), card.commands[3].Ins)
}
