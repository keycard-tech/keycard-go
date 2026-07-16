package types

import (
	"fmt"

	"github.com/keycard-tech/keycard-go/v4/tlv"
)

type lifeCycle byte

var (
	// TagGetStatusTemplate is the outer template tag for card status responses.
	TagGetStatusTemplate uint8 = 0xE3
)

const (
	LifeCycleOpReady     lifeCycle = 0x01
	LifeCycleInitialized           = 0x07
	LifeCycleSecured               = 0x0F
	LifeCycleCardLocked            = 0x7F
	LifeCycleTerminated            = 0xFF
)

func (lc lifeCycle) String() string {
	switch lc {
	case LifeCycleOpReady:
		return "OP_READY"
	case LifeCycleInitialized:
		return "INITIALIZED"
	case LifeCycleSecured:
		return "SECURED"
	case LifeCycleCardLocked:
		return "CARD_LOCKED"
	case LifeCycleTerminated:
		return "TERMINATED"
	default:
		return "UNKNOWN"
	}
}

type ErrInvalidLifeCycleValue struct {
	lc []byte
}

func (e *ErrInvalidLifeCycleValue) Error() string {
	return fmt.Sprintf("life cycle value must be 1 byte. got %d bytes: %x", len(e.lc), e.lc)
}

type CardStatus struct {
	lc lifeCycle
}

func (cs *CardStatus) LifeCycle() string {
	return cs.lc.String()
}

func ParseCardStatus(data []byte) (*CardStatus, error) {
	r := tlv.NewBerTlvReader(data)

	tpl, err := r.ReadPrimitive(TagGetStatusTemplate)
	if err != nil {
		return nil, err
	}

	inner := tlv.NewBerTlvReader(tpl)

	// Skip the 0x4F tag that precedes the lifecycle state.
	if err := inner.SkipPrimitive(); err != nil {
		return nil, err
	}

	// The lifecycle state uses a two-byte tag 0x9F 0x70.
	// We consume the leading 0x9F byte as a standalone tag, then read 0x70.
	if _, err := inner.ReadTag(); err != nil {
		return nil, err
	}
	lc, err := inner.ReadPrimitive(0x70)
	if err != nil {
		return nil, err
	}

	if len(lc) != 1 {
		return nil, &ErrInvalidLifeCycleValue{lc}
	}

	return &CardStatus{lifeCycle(lc[0])}, nil
}
