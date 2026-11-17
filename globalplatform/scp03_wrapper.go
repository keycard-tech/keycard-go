package globalplatform

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform/crypto"
)

// SCP03Wrapper applies the secure messaging of SCP03 (GP Card Spec v2.3 Amendment D)
// to commands and verifies the response protection negotiated with the card.
//
// Commands carry no ISO 7816-4 secure messaging data objects: the C-MAC is appended to
// the data field and the class byte marks the command as globally secure messaging.
type SCP03Wrapper struct {
	senc   []byte
	smac   []byte
	srmac  []byte
	level  SecurityLevel
	macLen int

	// chaining is the MAC chaining value: the full 16-byte CMAC of the previous command.
	chaining []byte
	// encCounter is incremented for every command of the session, including the ones
	// with no data to encrypt (Amendment D section 6.2.6).
	encCounter uint32
}

// ErrBadRMAC is returned when a response does not carry the expected R-MAC.
var ErrBadRMAC = errors.New("bad response mac")

// NewSCP03Wrapper returns a wrapper for a session established with the given session
// keys. macLen is 8 in S8 mode and 16 in S16 mode, as reported by the card.
func NewSCP03Wrapper(senc, smac, srmac []byte, level SecurityLevel, macLen int) (*SCP03Wrapper, error) {
	if len(senc) == 0 || len(smac) == 0 {
		return nil, errors.New("s-enc and s-mac session keys are required")
	}

	if level&levelRMAC != 0 && len(srmac) == 0 {
		return nil, errors.New("s-rmac session key is required by the security level")
	}

	if macLen != 8 && macLen != 16 {
		return nil, fmt.Errorf("bad mac length %d, expected 8 or 16", macLen)
	}

	return &SCP03Wrapper{
		senc:     senc,
		smac:     smac,
		srmac:    srmac,
		level:    level,
		macLen:   macLen,
		chaining: make([]byte, crypto.AESBlockSize),
	}, nil
}

// Wrap wraps a command adding C-DECRYPTION and C-MAC as required by the session level.
func (w *SCP03Wrapper) Wrap(cmd *apdu.Command) (*apdu.Command, error) {
	return w.wrap(cmd, true)
}

// WrapAuthenticate wraps the EXTERNAL AUTHENTICATE command, which is authenticated but
// never encrypted: the encryption counter sequence starts with the command following a
// successful authentication (Amendment D section 6.2.6).
func (w *SCP03Wrapper) WrapAuthenticate(cmd *apdu.Command) (*apdu.Command, error) {
	return w.wrap(cmd, false)
}

func (w *SCP03Wrapper) wrap(cmd *apdu.Command, encrypt bool) (*apdu.Command, error) {
	cla := cmd.Cla | 0x04
	data := cmd.Data

	if w.level&levelCDEC != 0 && encrypt {
		w.encCounter++

		if len(data) > 0 {
			icv, err := crypto.EncryptAESBlock(w.senc, w.counterBlock(false))
			if err != nil {
				return nil, err
			}

			encrypted, err := crypto.EncryptAESCBC(w.senc, icv, crypto.PadISO9797M2(data, crypto.AESBlockSize))
			if err != nil {
				return nil, err
			}

			data = encrypted
		}
	}

	lc := len(data)
	if w.level&levelCMAC != 0 {
		lc += w.macLen
	}

	if lc > 255 {
		return nil, fmt.Errorf("wrapped command data too long: %d bytes", lc)
	}

	if w.level&levelCMAC != 0 {
		mac, err := w.calculateMAC(cla, cmd.Ins, cmd.P1, cmd.P2, uint8(lc), data)
		if err != nil {
			return nil, err
		}

		withMAC := make([]byte, 0, len(data)+len(mac))
		withMAC = append(withMAC, data...)
		withMAC = append(withMAC, mac...)

		data = withMAC
	}

	newCmd := apdu.NewCommand(cla, cmd.Ins, cmd.P1, cmd.P2, data)
	if ok, le := cmd.Le(); ok {
		newCmd.SetLe(le)
	}

	return newCmd, nil
}

// Unwrap verifies the R-MAC of a response and removes the R-ENCRYPTION, returning the
// response the caller asked for.
func (w *SCP03Wrapper) Unwrap(resp *apdu.Response) (*apdu.Response, error) {
	if w.level&levelRMAC == 0 || !responseProtected(resp.Sw1, resp.Sw2) {
		return resp, nil
	}

	if len(resp.Data) < w.macLen {
		return nil, fmt.Errorf("response with status %04x carries no R-MAC", resp.Sw)
	}

	length := len(resp.Data) - w.macLen
	data := resp.Data[:length]

	buf := make([]byte, 0, len(w.chaining)+len(data)+2)
	buf = append(buf, w.chaining...)
	buf = append(buf, data...)
	buf = append(buf, resp.Sw1, resp.Sw2)

	calculated, err := crypto.CMAC(w.srmac, buf)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(calculated[:w.macLen], resp.Data[length:]) != 1 {
		return nil, ErrBadRMAC
	}

	if w.level&levelRENC != 0 && len(data) > 0 {
		icv, err := crypto.EncryptAESBlock(w.senc, w.counterBlock(true))
		if err != nil {
			return nil, err
		}

		decrypted, err := crypto.DecryptAESCBC(w.senc, icv, data)
		if err != nil {
			return nil, err
		}

		data, err = crypto.UnpadISO9797M2(decrypted, crypto.AESBlockSize)
		if err != nil {
			return nil, err
		}
	}

	return &apdu.Response{Data: data, Sw1: resp.Sw1, Sw2: resp.Sw2, Sw: resp.Sw}, nil
}

// maxDataSize returns the largest plain command data field that fits in a short APDU
// once the session protection is applied.
func (w *SCP03Wrapper) maxDataSize() int {
	available := 255

	if w.level&levelCMAC != 0 {
		available -= w.macLen
	}

	if w.level&levelCDEC == 0 {
		return available
	}

	// padding method 2 always adds at least one byte, so the padded length of n bytes
	// is 16 * ceil((n + 1) / 16).
	return crypto.AESBlockSize*(available/crypto.AESBlockSize) - 1
}

func (w *SCP03Wrapper) calculateMAC(cla, ins, p1, p2, lc byte, data []byte) ([]byte, error) {
	buf := make([]byte, 0, len(w.chaining)+5+len(data))
	buf = append(buf, w.chaining...)
	buf = append(buf, cla, ins, p1, p2, lc)
	buf = append(buf, data...)

	calculated, err := crypto.CMAC(w.smac, buf)
	if err != nil {
		return nil, err
	}

	// The chaining value advances only once the command is known to be well formed, so a
	// failure leaves the session in sync with the card.
	w.chaining = calculated

	return calculated[:w.macLen], nil
}

// counterBlock returns the block whose encryption with S-ENC gives the ICV. Response
// encryption uses the block of the last command with its most significant byte set to
// '80', keeping response ICVs different from command ICVs (Amendment D section 6.2.7).
func (w *SCP03Wrapper) counterBlock(response bool) []byte {
	block := make([]byte, crypto.AESBlockSize)
	block[0] = boolByte(response)
	block[len(block)-4] = byte(w.encCounter >> 24)
	block[len(block)-3] = byte(w.encCounter >> 16)
	block[len(block)-2] = byte(w.encCounter >> 8)
	block[len(block)-1] = byte(w.encCounter)

	return block
}

func boolByte(v bool) byte {
	if v {
		return 0x80
	}

	return 0x00
}

// responseProtected reports whether a response carries an R-MAC. Error status words
// return only the status bytes, unauthenticated (Amendment D section 6.2.5).
func responseProtected(sw1, sw2 byte) bool {
	return sw1 == 0x90 || sw1 == 0x62 || sw1 == 0x63
}
