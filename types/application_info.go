package types

import (
	"errors"
	"fmt"

	"github.com/keycard-tech/keycard-go/tlv"
)

var ErrWrongApplicationInfoTemplate = errors.New("wrong application info template")

type Capability uint8

const (
	CapabilitySecureChannel Capability = 1 << iota
	CapabilityKeyManagement
	CapabilityCredentialsManagement
	CapabilityNDEF
	CapabilityFactoryReset

	CapabilityAll = CapabilitySecureChannel |
		CapabilityKeyManagement |
		CapabilityCredentialsManagement |
		CapabilityNDEF |
		CapabilityFactoryReset
)

// App status flags
const (
	AppStatusInitialized = 0x10
	AppStatusLEEMode     = 0x20
)

const (
	TagSelectResponsePreInitialized uint8 = 0x80
	TagApplicationStatusTemplate    uint8 = 0xA3
	TagApplicationInfoTemplate      uint8 = 0xA4
	TagApplicationInfoCapabilities  uint8 = 0x8D
)

type ApplicationInfo struct {
	Installed              bool
	Initialized            bool
	InstanceUID            []byte
	SecureChannelPublicKey []byte
	Version                []byte
	AvailableSlots         []byte
	// KeyUID is the sha256 of of the master public key on the card.
	// It's empty if the card doesn't contain any key.
	KeyUID       []byte
	Capabilities Capability
	// V4+ fields
	CertData  []byte // V4+ certificate data (TLV_CERT)
	AppStatus uint8  // raw status byte
}

func (a *ApplicationInfo) HasCapability(c Capability) bool {
	return a.Capabilities&c == c
}

func (a *ApplicationInfo) HasSecureChannelCapability() bool {
	return a.HasCapability(CapabilitySecureChannel)
}

func (a *ApplicationInfo) HasKeyManagementCapability() bool {
	return a.HasCapability(CapabilityKeyManagement)
}

func (a *ApplicationInfo) HasCredentialsManagementCapability() bool {
	return a.HasCapability(CapabilityCredentialsManagement)
}

func (a *ApplicationInfo) HasNDEFCapability() bool {
	return a.HasCapability(CapabilityNDEF)
}

func (a *ApplicationInfo) HasFactoryResetCapability() bool {
	return a.HasCapability(CapabilityFactoryReset)
}

// HasSecureChannel returns true if the device supports Secure Channel.
func (a *ApplicationInfo) HasSecureChannel() bool {
	return a.HasSecureChannelCapability()
}

// IsLEEMode returns true if the device is in LEE mode.
func (a *ApplicationInfo) IsLEEMode() bool {
	return (a.AppStatus & AppStatusLEEMode) != 0
}

// PINRetries returns the remaining PIN retry count (V4+ only).
// Returns 0, false for older applet versions.
func (a *ApplicationInfo) PINRetries() (uint8, bool) {
	if a.AppVersion() < 0x0400 {
		return 0, false
	}
	return a.AppStatus & 0x0F, true
}

// AppVersionString returns the app version as a formatted string (e.g., "4.2").
func (a *ApplicationInfo) AppVersionString() string {
	v := a.AppVersion()
	return fmt.Sprintf("%d.%d", (v>>8)&0xFF, v&0xFF)
}

// AppVersion returns the app version (major in MSB, minor in LSB).
func (a *ApplicationInfo) AppVersion() uint16 {
	if len(a.Version) < 2 {
		return 0
	}
	return uint16(a.Version[0])<<8 | uint16(a.Version[1])
}

// Cert returns the raw certificate data (V4+ only).
func (a *ApplicationInfo) Cert() []byte {
	return a.CertData
}

// ParseApplicationInfo parses the TLV response from a SELECT command.
//
// Handles both uninitialized cards (only TLV_PUB_KEY present)
// and initialized cards (constructed TLV_APPLICATION_INFO_TEMPLATE).
func ParseApplicationInfo(data []byte) (*ApplicationInfo, error) {
	info := &ApplicationInfo{
		Installed: true,
	}

	reader := tlv.NewBerTlvReader(data)

	// Uninitialized card: only TLV_PUB_KEY present (tag 0x80)
	if reader.NextTagIs(tlv.TLV_PUB_KEY) {
		pubKey, err := reader.ReadPrimitive(tlv.TLV_PUB_KEY)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key from SELECT response: %w", err)
		}

		caps := CapabilityCredentialsManagement
		if len(pubKey) > 0 {
			caps = caps | CapabilitySecureChannel
		}

		info.SecureChannelPublicKey = pubKey
		info.Capabilities = caps
		return info, nil
	}

	// Initialized card: constructed TLV_APPLICATION_INFO_TEMPLATE
	_, err := reader.EnterConstructed(tlv.TLV_APPLICATION_INFO_TEMPLATE)
	if err != nil {
		return nil, ErrWrongApplicationInfoTemplate
	}

	appStatus := uint8(AppStatusInitialized)
	var instanceUID, pubKey, keyUID, certData []byte
	var appVersionBytes []byte
	var availableSlots []byte
	capabilities := CapabilityAll

	// instanceUID (0x8F) - present in V1-V3, absent in V4+
	if reader.NextTagIs(tlv.TLV_UID) {
		instanceUID, err = reader.ReadPrimitive(tlv.TLV_UID)
		if err != nil {
			return nil, fmt.Errorf("failed to read instance UID: %w", err)
		}
	}

	// secureChannelPubKey (0x80) - present in V1-V3, absent in V4+
	if reader.NextTagIs(tlv.TLV_PUB_KEY) {
		pubKey, err = reader.ReadPrimitive(tlv.TLV_PUB_KEY)
		if err != nil {
			return nil, fmt.Errorf("failed to read secure channel public key: %w", err)
		}
	}

	// appVersion (INTEGER 0x02) - present in all versions
	appVersionInt, err := reader.ReadInteger()
	if err != nil {
		return nil, fmt.Errorf("failed to read app version: %w", err)
	}
	appVersionBytes = []byte{byte(appVersionInt >> 8), byte(appVersionInt)}

	// appStatus (0x8C) - initialized, lee mode, pin retries
	if reader.NextTagIs(tlv.TLV_STATUS) {
		statusBytes, err := reader.ReadPrimitive(tlv.TLV_STATUS)
		if err != nil {
			return nil, fmt.Errorf("failed to read app status: %w", err)
		}
		if len(statusBytes) == 0 {
			return nil, errors.New("app status TLV has empty value")
		}
		appStatus = statusBytes[0]
	}

	initialized := (appStatus & AppStatusInitialized) == AppStatusInitialized

	// freePairingSlots (INTEGER 0x02) - present in V1-V3, absent in V4+
	if reader.NextTagIs(tlv.TLV_INT) {
		slotsInt, err := reader.ReadInteger()
		if err != nil {
			return nil, fmt.Errorf("failed to read free pairing slots: %w", err)
		}
		availableSlots = []byte{byte(slotsInt)}
	}

	// keyUID (0x8E) - present in all versions
	keyUID, err = reader.ReadPrimitive(tlv.TLV_KEY_UID)
	if err != nil {
		return nil, fmt.Errorf("failed to read key UID: %w", err)
	}

	// capabilities (0x8D) - present in V2+
	if reader.NextTagIs(tlv.TLV_CAPABILITIES) {
		capsBytes, err := reader.ReadPrimitive(tlv.TLV_CAPABILITIES)
		if err != nil {
			return nil, fmt.Errorf("failed to read capabilities: %w", err)
		}
		if len(capsBytes) == 0 {
			return nil, errors.New("capabilities TLV has empty value")
		}
		capabilities = Capability(capsBytes[0])
	}

	// certData (0x8A) - present in V4+
	if reader.NextTagIs(tlv.TLV_CERT) {
		certData, err = reader.ReadPrimitive(tlv.TLV_CERT)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate data: %w", err)
		}
	}

	info.Initialized = initialized
	info.InstanceUID = instanceUID
	info.SecureChannelPublicKey = pubKey
	info.Version = appVersionBytes
	info.AvailableSlots = availableSlots
	info.KeyUID = keyUID
	info.Capabilities = capabilities
	info.CertData = certData
	info.AppStatus = appStatus

	return info, nil
}
