package keycard

import (
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/identifiers"
	"github.com/status-im/keycard-go/types"
)

// IdentCommandSet is the API for interacting with the Ident applet.
//
// The Ident applet provides a simple signing interface without secure
// channel or PIN protection.
type IdentCommandSet struct {
	c types.Channel
}

// NewIdentCommandSet creates an IdentCommandSet using the given APDU channel.
func NewIdentCommandSet(c types.Channel) *IdentCommandSet {
	return &IdentCommandSet{c: c}
}

// Select selects the default instance of the Ident applet.
func (cs *IdentCommandSet) Select() error {
	cmd := globalplatform.NewCommandSelect(identifiers.IdentInstanceAID)
	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)
	return apdu.CheckOK(resp, err)
}

// StoreData sends a STORE DATA APDU to the Ident applet.
func (cs *IdentCommandSet) StoreData(data []byte) (*apdu.Response, error) {
	cmd := apdu.NewCommand(
		globalplatform.ClaGp,
		InsStoreData,
		0x00,
		0x00,
		data,
	)
	resp, err := cs.c.Send(cmd)
	if err = apdu.CheckOK(resp, err); err != nil {
		return nil, err
	}
	return resp, nil
}


