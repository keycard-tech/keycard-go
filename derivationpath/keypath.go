package derivationpath

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	SourceMaster  uint8 = 0x00
	SourceParent  uint8 = 0x40
	SourceCurrent uint8 = 0x80
)

// KeyPath is a BIP32 derivation path with source indicator.
type KeyPath struct {
	source uint8
	data   []byte
}

// KeyPathFromString parses a BIP32 path string like "m/44'/0'/0'/0/0".
func KeyPathFromString(path string) (*KeyPath, error) {
	components := strings.Split(path, "/")
	if len(components) == 0 {
		return nil, fmt.Errorf("empty path")
	}

	first := strings.TrimSpace(components[0])
	if first == "" {
		return nil, fmt.Errorf("path must start with m, .., ., or a number")
	}

	components = components[1:]

	var source uint8
	switch first {
	case "m":
		source = SourceMaster
	case "..":
		source = SourceParent
	case ".":
		source = SourceCurrent
	default:
		// Not a source indicator, treat as first component with SOURCE_CURRENT
		components = append([]string{first}, components...)
		source = SourceCurrent
	}

	if len(components) > 10 {
		return nil, fmt.Errorf("too many path components (max 10)")
	}

	data := make([]byte, 0, len(components)*4)
	for _, c := range components {
		num, err := parsePathComponent(c)
		if err != nil {
			return nil, err
		}
		data = append(data, byte(num>>24), byte(num>>16), byte(num>>8), byte(num))
	}

	return &KeyPath{source: source, data: data}, nil
}

// KeyPathFromRaw constructs a KeyPath from raw bytes with a source.
func KeyPathFromRaw(data []byte, source uint8) *KeyPath {
	cp := make([]byte, len(data))
	copy(cp, data)
	return &KeyPath{source: source, data: cp}
}

// KeyPathFromRawMaster constructs a KeyPath from raw bytes with SOURCE_MASTER.
func KeyPathFromRawMaster(data []byte) *KeyPath {
	return KeyPathFromRaw(data, SourceMaster)
}

// Source returns the source byte.
func (kp *KeyPath) Source() uint8 {
	return kp.source
}

// Data returns the raw path data.
func (kp *KeyPath) Data() []byte {
	return kp.data
}

// String reverse-encodes to a BIP32 path string.
func (kp *KeyPath) String() string {
	var sb strings.Builder

	switch kp.source {
	case SourceMaster:
		sb.WriteString("m")
	case SourceParent:
		sb.WriteString("..")
	case SourceCurrent:
		sb.WriteString(".")
	default:
		sb.WriteString(".")
	}

	for i := 0; i+4 <= len(kp.data); i += 4 {
		chunk := kp.data[i : i+4]
		hardened := chunk[0]&0x80 != 0
		num := ((uint32(chunk[0]) & 0x7F) << 24) |
			(uint32(chunk[1]) << 16) |
			(uint32(chunk[2]) << 8) |
			uint32(chunk[3])
		sb.WriteString("/")
		sb.WriteString(strconv.FormatUint(uint64(num), 10))
		if hardened {
			sb.WriteString("'")
		}
	}

	return sb.String()
}

func parsePathComponent(s string) (uint32, error) {
	isHardened := false
	if strings.HasSuffix(s, "'") {
		isHardened = true
		s = strings.TrimSuffix(s, "'")
	}

	if s == "" {
		return 0, fmt.Errorf("empty path component")
	}

	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("no sign allowed in path component: %s", s)
	}

	num, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid path component: %s", s)
	}

	if num > 0x7FFFFFFF {
		return 0, fmt.Errorf("path component too large: %s", s)
	}

	if isHardened {
		return uint32(num) | 0x80000000, nil
	}
	return uint32(num), nil
}
