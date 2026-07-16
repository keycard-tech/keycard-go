package tlv

import "fmt"

// ============================================================================
// TLV tag constants (single-byte, uint8)
// ============================================================================

// BOOLEAN tag
const TLV_BOOL uint8 = 0x01

// INTEGER tag
const TLV_INT uint8 = 0x02

// SEQUENCE tag (used in ECDSA signatures)
const TLV_ECDSA_TEMPLATE uint8 = 0x30

// Signature template
const TLV_SIGNATURE_TEMPLATE uint8 = 0xA0

// Key template
const TLV_KEY_TEMPLATE uint8 = 0xA1

// Application status template
const TLV_APPLICATION_STATUS_TEMPLATE uint8 = 0xA3

// Application info template
const TLV_APPLICATION_INFO_TEMPLATE uint8 = 0xA4

// Public key
const TLV_PUB_KEY uint8 = 0x80

// Private key
const TLV_PRIV_KEY uint8 = 0x81

// Chain code
const TLV_CHAIN_CODE uint8 = 0x82

// Certificate
const TLV_CERT uint8 = 0x8A

// Capabilities
const TLV_CAPABILITIES uint8 = 0x8D

// Key UID
const TLV_KEY_UID uint8 = 0x8E

// UID (instance UID)
const TLV_UID uint8 = 0x8F

// Status
const TLV_STATUS uint8 = 0x8C

// Public data
const TLV_PUB_DATA uint8 = 0x82

// ============================================================================
// BER length encoding
// ============================================================================

// EncodeBerLength encodes a length in BER-TLV encoding: short form (1 byte,
// 0..=127) or long form (a 0x81-0x84 prefix followed by 1-4 big-endian
// length bytes).
func EncodeBerLength(length uint32) []byte {
	if length < 0x80 {
		return []byte{uint8(length)}
	} else if length < 0x100 {
		return []byte{0x81, uint8(length)}
	} else if length < 0x10000 {
		return []byte{0x82, uint8(length >> 8), uint8(length)}
	} else if length < 0x1000000 {
		return []byte{0x83, uint8(length >> 16), uint8(length >> 8), uint8(length)}
	}
	return []byte{0x84, uint8(length >> 24), uint8(length >> 16), uint8(length >> 8), uint8(length)}
}

// DecodeBerLength decodes a BER-TLV length field from data at offset off.
// Returns (value, nextOffset). Rejects indefinite length (0x80) and any long
// form claiming more than 4 length bytes.
func DecodeBerLength(data []byte, off int) (uint32, int, error) {
	if off >= len(data) {
		return 0, off, fmt.Errorf("end of buffer, no length to read")
	}

	first := int(data[off])
	off++

	if first < 0x80 {
		// Short form: length is the byte value directly
		return uint32(first), off, nil
	} else if first == 0x80 {
		// Indefinite length — not supported
		return 0, off, fmt.Errorf("indefinite length encoding not supported")
	}

	// Long form: low 7 bits are the number of length bytes that follow
	numBytes := first & 0x7F
	if numBytes > 4 {
		return 0, off, fmt.Errorf("length encoding too long: %d bytes", numBytes)
	}
	if off+numBytes > len(data) {
		return 0, off, fmt.Errorf("end of buffer while reading length")
	}

	var length uint32
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | uint32(data[off+i])
	}
	off += numBytes
	return length, off, nil
}

// ============================================================================
// BerTlvReader
// ============================================================================

// BerTlvReader is a cursor-based BER-TLV reader over a byte slice.
type BerTlvReader struct {
	buffer []byte
	pos    int
}

// NewBerTlvReader creates a reader over the given buffer.
func NewBerTlvReader(buffer []byte) *BerTlvReader {
	return &BerTlvReader{buffer: buffer, pos: 0}
}

// ReadTag reads a single-byte tag.
func (r *BerTlvReader) ReadTag() (uint8, error) {
	if r.pos >= len(r.buffer) {
		return 0, fmt.Errorf("end of buffer, no tag to read")
	}
	tag := r.buffer[r.pos]
	r.pos++
	return tag, nil
}

// NextTagIs peeks at the next tag without consuming it.
// Returns true if the next byte matches the expected tag.
func (r *BerTlvReader) NextTagIs(expected uint8) bool {
	if r.pos < len(r.buffer) {
		return r.buffer[r.pos] == expected
	}
	return false
}

// ReadLength reads the TLV length field.
// Supports short form (1 byte, 0..=127) and long form (1..=4 bytes).
func (r *BerTlvReader) ReadLength() (uint32, error) {
	length, nextPos, err := DecodeBerLength(r.buffer, r.pos)
	if err != nil {
		return 0, err
	}
	r.pos = nextPos
	return length, nil
}

// EnterConstructed asserts next tag matches, reads and returns the length.
func (r *BerTlvReader) EnterConstructed(tag uint8) (uint32, error) {
	actualTag, err := r.ReadTag()
	if err != nil {
		return 0, err
	}
	if actualTag != tag {
		return 0, fmt.Errorf("expected tag 0x%02X but got 0x%02X", tag, actualTag)
	}
	return r.ReadLength()
}

// ReadPrimitive asserts next tag matches, reads length, returns the value bytes.
func (r *BerTlvReader) ReadPrimitive(tag uint8) ([]byte, error) {
	actualTag, err := r.ReadTag()
	if err != nil {
		return nil, err
	}
	if actualTag != tag {
		return nil, fmt.Errorf("expected tag 0x%02X but got 0x%02X", tag, actualTag)
	}
	length, err := r.ReadLength()
	if err != nil {
		return nil, err
	}
	if r.pos+int(length) > len(r.buffer) {
		return nil, fmt.Errorf("not enough data for value: need %d bytes, have %d", length, len(r.buffer)-r.pos)
	}
	value := r.buffer[r.pos : r.pos+int(length)]
	r.pos += int(length)
	return value, nil
}

// ReadPrimitiveIfPresent checks if the next tag matches. If it does, reads and
// returns the value bytes. If the next tag does not match, returns (nil, nil) —
// not an error — so callers can handle optional TLV fields.
func (r *BerTlvReader) ReadPrimitiveIfPresent(tag uint8) ([]byte, error) {
	if !r.NextTagIs(tag) {
		return nil, nil
	}
	return r.ReadPrimitive(tag)
}

// Skip advances past the current TLV (tag already consumed, length just read).
func (r *BerTlvReader) Skip(length uint32) error {
	if r.pos+int(length) > len(r.buffer) {
		return fmt.Errorf("not enough data to skip: need %d bytes, have %d", length, len(r.buffer)-r.pos)
	}
	r.pos += int(length)
	return nil
}

// SkipPrimitive reads and discards the next TLV (tag + length + value).
func (r *BerTlvReader) SkipPrimitive() error {
	_, err := r.ReadTag()
	if err != nil {
		return err
	}
	length, err := r.ReadLength()
	if err != nil {
		return err
	}
	return r.Skip(length)
}

// ReadBoolean reads a BOOLEAN tag (0x01), returns true if value byte is 0xFF.
func (r *BerTlvReader) ReadBoolean() (bool, error) {
	value, err := r.ReadPrimitive(TLV_BOOL)
	if err != nil {
		return false, err
	}
	if len(value) != 1 {
		return false, fmt.Errorf("BOOLEAN value must be 1 byte, got %d", len(value))
	}
	return value[0] == 0xFF, nil
}

// ReadInteger reads an INTEGER tag (0x02), decodes as big-endian.
func (r *BerTlvReader) ReadInteger() (int32, error) {
	value, err := r.ReadPrimitive(TLV_INT)
	if err != nil {
		return 0, err
	}
	if len(value) == 0 || len(value) > 4 {
		return 0, fmt.Errorf("INTEGER value must be 1-4 bytes, got %d", len(value))
	}
	var result int32
	for _, b := range value {
		result = (result << 8) | int32(b)
	}
	return result, nil
}

// PeekUnread returns remaining unconsumed bytes.
func (r *BerTlvReader) PeekUnread() []byte {
	if r.pos < len(r.buffer) {
		return r.buffer[r.pos:]
	}
	return []byte{}
}

// Pos returns the current position in the buffer.
func (r *BerTlvReader) Pos() int {
	return r.pos
}

// Len returns the total buffer length.
func (r *BerTlvReader) Len() int {
	return len(r.buffer)
}

// IsEmpty returns true if the buffer is empty.
func (r *BerTlvReader) IsEmpty() bool {
	return len(r.buffer) == 0
}

// Buffer returns a reference to the underlying buffer.
func (r *BerTlvReader) Buffer() []byte {
	return r.buffer
}

// Advance advances the read position by count bytes.
func (r *BerTlvReader) Advance(count int) {
	if r.pos+count > len(r.buffer) {
		r.pos = len(r.buffer)
	} else {
		r.pos += count
	}
}

// ============================================================================
// BerTlvWriter
// ============================================================================

// BerTlvWriter is a builder for constructing BER-TLV byte sequences.
type BerTlvWriter struct {
	buffer []byte
}

// NewBerTlvWriter creates a new empty writer.
func NewBerTlvWriter() *BerTlvWriter {
	return &BerTlvWriter{}
}

// WriteNumLength writes a length field in BER-TLV encoding (short or long form).
func (w *BerTlvWriter) WriteNumLength(length uint32) {
	w.buffer = append(w.buffer, EncodeBerLength(length)...)
}

// WriteTag writes a single tag byte.
func (w *BerTlvWriter) WriteTag(tag uint8) {
	w.buffer = append(w.buffer, tag)
}

// WritePrimitive writes tag + length + value.
func (w *BerTlvWriter) WritePrimitive(tag uint8, value []byte) {
	w.buffer = append(w.buffer, tag)
	w.WriteNumLength(uint32(len(value)))
	w.buffer = append(w.buffer, value...)
}

// WriteConstructed writes a constructed TLV: tag + total length, then invokes
// contentFn to write inner TLVs.
func (w *BerTlvWriter) WriteConstructed(tag uint8, contentFn func(*BerTlvWriter)) {
	// First, write content to a temporary buffer
	tempWriter := NewBerTlvWriter()
	contentFn(tempWriter)
	content := tempWriter.ToBytes()

	// Write tag + length + content
	w.buffer = append(w.buffer, tag)
	w.WriteNumLength(uint32(len(content)))
	w.buffer = append(w.buffer, content...)
}

// WriteBoolean writes a BOOLEAN TLV.
func (w *BerTlvWriter) WriteBoolean(tag uint8, value bool) {
	if value {
		w.WritePrimitive(tag, []byte{0xFF})
	} else {
		w.WritePrimitive(tag, []byte{0x00})
	}
}

// WriteInteger writes an INTEGER TLV.
func (w *BerTlvWriter) WriteInteger(tag uint8, value int32) {
	bytes := make([]byte, 4)
	bytes[0] = byte(value >> 24)
	bytes[1] = byte(value >> 16)
	bytes[2] = byte(value >> 8)
	bytes[3] = byte(value)

	// Strip leading zero bytes (but keep at least one byte)
	start := 0
	for start < 3 && bytes[start] == 0 {
		start++
	}
	// For negative values, keep the sign byte
	if value < 0 {
		start = 0
	}

	w.WritePrimitive(tag, bytes[start:])
}

// ToBytes returns the accumulated bytes.
func (w *BerTlvWriter) ToBytes() []byte {
	result := make([]byte, len(w.buffer))
	copy(result, w.buffer)
	return result
}

// AsSlice returns a reference to the accumulated bytes.
func (w *BerTlvWriter) AsSlice() []byte {
	return w.buffer
}
