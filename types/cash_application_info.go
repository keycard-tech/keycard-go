package types

import (
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/tlv"
)

type CashApplicationInfo struct {
	Installed  bool
	PublicKey  []byte
	PublicData []byte
	Version    []byte
}

func ParseCashApplicationInfo(data []byte) (*CashApplicationInfo, error) {
	info := &CashApplicationInfo{}

	if data[0] != tlv.TLV_APPLICATION_INFO_TEMPLATE {
		return nil, ErrWrongApplicationInfoTemplate
	}

	info.Installed = true

	r := tlv.NewBerTlvReader(data)
	_, err := r.EnterConstructed(tlv.TLV_APPLICATION_INFO_TEMPLATE)
	if err != nil {
		return nil, err
	}

	pubKey, err := r.ReadPrimitive(tlv.TLV_PUB_KEY)
	if err != nil {
		return nil, err
	}

	appVersion, err := r.ReadPrimitive(tlv.TLV_INT)
	if err != nil {
		return nil, err
	}

	pubData, err := r.ReadPrimitive(tlv.TLV_PUB_DATA)
	if err != nil {
		return nil, err
	}

	if uint32(r.Pos()) != uint32(len(data)) {
		return nil, fmt.Errorf("unexpected trailing data in application info")
	}

	info.PublicKey = pubKey
	info.PublicData = pubData
	info.Version = appVersion

	return info, nil
}
