package types

import (
	"github.com/keycard-tech/keycard-go/v4/derivationpath"
	"github.com/keycard-tech/keycard-go/v4/tlv"
)

type ApplicationStatus struct {
	PinRetryCount  int
	PUKRetryCount  int
	KeyInitialized bool
	Path           string
}

// ParseApplicationStatus parses the TLV response from a GET STATUS command.
func ParseApplicationStatus(data []byte) (*ApplicationStatus, error) {
	reader := tlv.NewBerTlvReader(data)

	_, err := reader.EnterConstructed(tlv.TLV_APPLICATION_STATUS_TEMPLATE)
	if err != nil {
		// Fall back to key path status parsing
		return parseKeyPathStatus(data)
	}

	appStatus := &ApplicationStatus{}

	// PIN retry count (INTEGER)
	pinRetryInt, err := reader.ReadInteger()
	if err == nil {
		appStatus.PinRetryCount = int(pinRetryInt)
	}

	// PUK retry count (INTEGER)
	pukRetryInt, err := reader.ReadInteger()
	if err == nil {
		appStatus.PUKRetryCount = int(pukRetryInt)
	}

	// Key initialized (BOOLEAN)
	keyInitialized, err := reader.ReadBoolean()
	if err == nil {
		appStatus.KeyInitialized = keyInitialized
	}

	return appStatus, nil
}

func parseKeyPathStatus(data []byte) (*ApplicationStatus, error) {
	appStatus := &ApplicationStatus{}

	path, err := derivationpath.EncodeFromBytes(data)
	if err != nil {
		return nil, err
	}

	appStatus.Path = path

	return appStatus, nil
}
