package globalplatform

import (
	"bytes"
	"encoding/binary"

	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform/crypto"
)

// SCP02Wrapper is a wrapper for apdu commands inside a global platform secure channel.
type SCP02Wrapper struct {
	macKey []byte
	icv    []byte
}

// scp02MACLength is the length of the retail MAC appended to every command.
const scp02MACLength = 8

// NewSCP02Wrapper returns a new SCP02Wrapper using the specified key for MAC generation.
func NewSCP02Wrapper(macKey []byte) *SCP02Wrapper {
	return &SCP02Wrapper{
		macKey: macKey,
		icv:    crypto.NullBytes8,
	}
}

// Wrap wraps the apdu command adding the MAC to the end of the command.
// Future implementations will encrypt the message when needed.
func (w *SCP02Wrapper) Wrap(cmd *apdu.Command) (*apdu.Command, error) {
	macData := new(bytes.Buffer)

	cla := cmd.Cla | 0x04
	if err := binary.Write(macData, binary.BigEndian, cla); err != nil {
		return nil, err
	}

	if err := binary.Write(macData, binary.BigEndian, cmd.Ins); err != nil {
		return nil, err
	}

	if err := binary.Write(macData, binary.BigEndian, cmd.P1); err != nil {
		return nil, err
	}

	if err := binary.Write(macData, binary.BigEndian, cmd.P2); err != nil {
		return nil, err
	}

	if err := binary.Write(macData, binary.BigEndian, uint8(len(cmd.Data)+scp02MACLength)); err != nil {
		return nil, err
	}

	if err := binary.Write(macData, binary.BigEndian, cmd.Data); err != nil {
		return nil, err
	}

	var (
		icv []byte
		err error
	)

	if bytes.Equal(w.icv, crypto.NullBytes8) {
		icv = w.icv
	} else {
		icv, err = crypto.EncryptICV(w.macKey, w.icv)
		if err != nil {
			return nil, err
		}
	}

	mac, err := crypto.MacFull3DES(w.macKey, macData.Bytes(), icv)
	if err != nil {
		return nil, err
	}

	newData := make([]byte, 0)
	newData = append(newData, cmd.Data...)
	newData = append(newData, mac...)

	w.icv = mac

	newCmd := apdu.NewCommand(cla, cmd.Ins, cmd.P1, cmd.P2, newData)
	if ok, le := cmd.Le(); ok {
		newCmd.SetLe(le)
	}

	return newCmd, nil
}

// WrapAuthenticate wraps the EXTERNAL AUTHENTICATE command, which SCP02 protects like
// any other command of the session.
func (w *SCP02Wrapper) WrapAuthenticate(cmd *apdu.Command) (*apdu.Command, error) {
	return w.Wrap(cmd)
}

// Unwrap returns the response unchanged, SCP02 sessions negotiate no response protection.
func (w *SCP02Wrapper) Unwrap(resp *apdu.Response) (*apdu.Response, error) {
	return resp, nil
}

// maxDataSize returns the largest plain command data field that fits in a short APDU
// along with the MAC.
func (w *SCP02Wrapper) maxDataSize() int {
	return 255 - scp02MACLength
}
