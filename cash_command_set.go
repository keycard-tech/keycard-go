package keycard

import (
	"github.com/keycard-tech/keycard-go/apdu"
	"github.com/keycard-tech/keycard-go/globalplatform"
	"github.com/keycard-tech/keycard-go/identifiers"
	"github.com/keycard-tech/keycard-go/types"
)

type CashCommandSet struct {
	c                   types.Channel
	CashApplicationInfo *types.CashApplicationInfo
}

func NewCashCommandSet(c types.Channel) *CashCommandSet {
	return &CashCommandSet{
		c:                   c,
		CashApplicationInfo: &types.CashApplicationInfo{},
	}
}

func (cs *CashCommandSet) Select() error {
	cmd := globalplatform.NewCommandSelect(identifiers.CashInstanceAID)
	cmd.SetLe(0)
	resp, err := cs.c.Send(cmd)
	if err = apdu.CheckOK(resp, err); err != nil {
		return err
	}

	appInfo, err := types.ParseCashApplicationInfo(resp.Data)
	if err != nil {
		return err
	}

	cs.CashApplicationInfo = appInfo

	return nil
}

func (cs *CashCommandSet) Sign(data []byte) (*types.Signature, error) {
	return cs.SignWithAlgo(data, 0x00)
}

func (cs *CashCommandSet) SignWithAlgo(data []byte, algo uint8) (*types.Signature, error) {
	cmd, err := NewCommandSign(data, 0x00, algo, "")
	if err != nil {
		return nil, err
	}

	resp, err := cs.c.Send(cmd)
	if err = apdu.CheckOK(resp, err); err != nil {
		return nil, err
	}

	return types.ParseSignature(data, resp.Data)
}


