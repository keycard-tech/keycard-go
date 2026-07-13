package tlv

import (
	"testing"
)

// ============================================================================
// BER length encoding tests
// ============================================================================

func TestEncodeBerLength_Short(t *testing.T) {
	tests := []struct {
		input    uint32
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{10, []byte{0x0A}},
		{127, []byte{0x7F}},
	}
	for _, tt := range tests {
		result := EncodeBerLength(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("EncodeBerLength(%d): got %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range tt.expected {
			if result[i] != tt.expected[i] {
				t.Errorf("EncodeBerLength(%d): got %v, want %v", tt.input, result, tt.expected)
				break
			}
		}
	}
}

func TestEncodeBerLength_Long(t *testing.T) {
	tests := []struct {
		input    uint32
		expected []byte
	}{
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xFF}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xFF, 0xFF}},
		{65536, []byte{0x83, 0x01, 0x00, 0x00}},
		{16777215, []byte{0x83, 0xFF, 0xFF, 0xFF}},
		{16777216, []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		result := EncodeBerLength(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("EncodeBerLength(%d): got %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range tt.expected {
			if result[i] != tt.expected[i] {
				t.Errorf("EncodeBerLength(%d): got %v, want %v", tt.input, result, tt.expected)
				break
			}
		}
	}
}

func TestDecodeBerLength_Short(t *testing.T) {
	val, off, err := DecodeBerLength([]byte{0x0A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 10 {
		t.Errorf("expected 10, got %d", val)
	}
	if off != 1 {
		t.Errorf("expected offset 1, got %d", off)
	}
}

func TestDecodeBerLength_Long1Byte(t *testing.T) {
	val, off, err := DecodeBerLength([]byte{0x81, 0xFF}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 255 {
		t.Errorf("expected 255, got %d", val)
	}
	if off != 2 {
		t.Errorf("expected offset 2, got %d", off)
	}
}

func TestDecodeBerLength_Long2Bytes(t *testing.T) {
	val, off, err := DecodeBerLength([]byte{0x82, 0x01, 0x00}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 256 {
		t.Errorf("expected 256, got %d", val)
	}
	if off != 3 {
		t.Errorf("expected offset 3, got %d", off)
	}
}

func TestDecodeBerLength_Indefinite(t *testing.T) {
	_, _, err := DecodeBerLength([]byte{0x80}, 0)
	if err == nil {
		t.Error("expected error for indefinite length")
	}
}

func TestDecodeBerLength_TooLong(t *testing.T) {
	_, _, err := DecodeBerLength([]byte{0x85, 0x00, 0x00, 0x00, 0x01, 0x00}, 0)
	if err == nil {
		t.Error("expected error for length encoding > 4 bytes")
	}
}

func TestDecodeBerLength_EndOfBuffer(t *testing.T) {
	_, _, err := DecodeBerLength([]byte{}, 0)
	if err == nil {
		t.Error("expected error for empty buffer")
	}
}

func TestDecodeBerLength_EndOfBufferInLongForm(t *testing.T) {
	_, _, err := DecodeBerLength([]byte{0x82, 0x01}, 0)
	if err == nil {
		t.Error("expected error for truncated long form")
	}
}

// ============================================================================
// BerTlvReader tests
// ============================================================================

func TestReadTag(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x80, 0x01, 0xAB})
	tag, err := reader.ReadTag()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag != 0x80 {
		t.Errorf("expected tag 0x80, got 0x%02X", tag)
	}
}

func TestReadTag_EndOfBuffer(t *testing.T) {
	reader := NewBerTlvReader([]byte{})
	_, err := reader.ReadTag()
	if err == nil {
		t.Error("expected error for empty buffer")
	}
}

func TestReadLength_Short(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x0A})
	length, err := reader.ReadLength()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 10 {
		t.Errorf("expected 10, got %d", length)
	}
}

func TestReadLength_Long1Byte(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x81, 0xFF})
	length, err := reader.ReadLength()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 255 {
		t.Errorf("expected 255, got %d", length)
	}
}

func TestReadLength_Long2Bytes(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x82, 0x01, 0x00})
	length, err := reader.ReadLength()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 256 {
		t.Errorf("expected 256, got %d", length)
	}
}

func TestNextTagIs(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x80, 0x01, 0xAB})
	if !reader.NextTagIs(0x80) {
		t.Error("expected next tag to be 0x80")
	}
	if reader.NextTagIs(0x81) {
		t.Error("expected next tag to NOT be 0x81")
	}
	// Should not advance position
	if !reader.NextTagIs(0x80) {
		t.Error("expected next tag to still be 0x80 after peek")
	}
}

func TestNextTagIs_Empty(t *testing.T) {
	reader := NewBerTlvReader([]byte{})
	if reader.NextTagIs(0x80) {
		t.Error("expected false for empty buffer")
	}
}

func TestReadPrimitive(t *testing.T) {
	data := []byte{0x80, 0x03, 0x01, 0x02, 0x03, 0x81, 0x02, 0xAA, 0xBB}
	reader := NewBerTlvReader(data)

	val, err := reader.ReadPrimitive(0x80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(val) != 3 || val[0] != 0x01 || val[1] != 0x02 || val[2] != 0x03 {
		t.Errorf("expected [0x01, 0x02, 0x03], got %v", val)
	}

	val2, err := reader.ReadPrimitive(0x81)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(val2) != 2 || val2[0] != 0xAA || val2[1] != 0xBB {
		t.Errorf("expected [0xAA, 0xBB], got %v", val2)
	}
}

func TestReadPrimitive_WrongTag(t *testing.T) {
	data := []byte{0x80, 0x01, 0x01}
	reader := NewBerTlvReader(data)
	_, err := reader.ReadPrimitive(0x81)
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

func TestReadPrimitive_NotEnoughData(t *testing.T) {
	data := []byte{0x80, 0x10, 0x01, 0x02}
	reader := NewBerTlvReader(data)
	_, err := reader.ReadPrimitive(0x80)
	if err == nil {
		t.Error("expected error for not enough data")
	}
}

func TestReadBoolean(t *testing.T) {
	// True
	data := []byte{0x01, 0x01, 0xFF}
	reader := NewBerTlvReader(data)
	val, err := reader.ReadBoolean()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !val {
		t.Error("expected true")
	}

	// False
	data = []byte{0x01, 0x01, 0x00}
	reader = NewBerTlvReader(data)
	val, err = reader.ReadBoolean()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val {
		t.Error("expected false")
	}
}

func TestReadInteger(t *testing.T) {
	// Single byte
	data := []byte{0x02, 0x01, 0x05}
	reader := NewBerTlvReader(data)
	val, err := reader.ReadInteger()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 5 {
		t.Errorf("expected 5, got %d", val)
	}

	// Two bytes
	data = []byte{0x02, 0x02, 0x00, 0x64}
	reader = NewBerTlvReader(data)
	val, err = reader.ReadInteger()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 100 {
		t.Errorf("expected 100, got %d", val)
	}

	// Three bytes
	data = []byte{0x02, 0x03, 0x00, 0x01, 0x00}
	reader = NewBerTlvReader(data)
	val, err = reader.ReadInteger()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 256 {
		t.Errorf("expected 256, got %d", val)
	}
}

func TestPeekUnread(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	reader := NewBerTlvReader(data)
	if len(reader.PeekUnread()) != 4 {
		t.Errorf("expected 4 unread bytes, got %d", len(reader.PeekUnread()))
	}
	reader.ReadTag()
	if len(reader.PeekUnread()) != 3 {
		t.Errorf("expected 3 unread bytes, got %d", len(reader.PeekUnread()))
	}
}

func TestEnterConstructed(t *testing.T) {
	data := []byte{0xA0, 0x05, 0x80, 0x03, 0x01, 0x02, 0x03}
	reader := NewBerTlvReader(data)
	length, err := reader.EnterConstructed(0xA0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 5 {
		t.Errorf("expected length 5, got %d", length)
	}
}

func TestEnterConstructed_WrongTag(t *testing.T) {
	data := []byte{0xA0, 0x01, 0x01}
	reader := NewBerTlvReader(data)
	_, err := reader.EnterConstructed(0xA1)
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

func TestAdvance(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	reader := NewBerTlvReader(data)
	reader.Advance(2)
	if reader.Pos() != 2 {
		t.Errorf("expected position 2, got %d", reader.Pos())
	}
	reader.Advance(100) // should clamp to buffer end
	if reader.Pos() != len(data) {
		t.Errorf("expected position %d, got %d", len(data), reader.Pos())
	}
}

func TestReaderLen_Pos_IsEmpty(t *testing.T) {
	reader := NewBerTlvReader([]byte{0x01, 0x02})
	if reader.Len() != 2 {
		t.Errorf("expected len 2, got %d", reader.Len())
	}
	if reader.Pos() != 0 {
		t.Errorf("expected pos 0, got %d", reader.Pos())
	}
	if reader.IsEmpty() {
		t.Error("expected !IsEmpty")
	}

	reader2 := NewBerTlvReader([]byte{})
	if !reader2.IsEmpty() {
		t.Error("expected IsEmpty")
	}
}

// ============================================================================
// BerTlvWriter tests
// ============================================================================

func TestWritePrimitive(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WritePrimitive(0x80, []byte{0x01, 0x02, 0x03})
	expected := []byte{0x80, 0x03, 0x01, 0x02, 0x03}
	result := writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestWriteBoolean(t *testing.T) {
	// True
	writer := NewBerTlvWriter()
	writer.WriteBoolean(0x01, true)
	expected := []byte{0x01, 0x01, 0xFF}
	result := writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}

	// False
	writer = NewBerTlvWriter()
	writer.WriteBoolean(0x01, false)
	expected = []byte{0x01, 0x01, 0x00}
	result = writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestWriteInteger(t *testing.T) {
	// Small value
	writer := NewBerTlvWriter()
	writer.WriteInteger(0x02, 5)
	expected := []byte{0x02, 0x01, 0x05}
	result := writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}

	// Larger value
	writer = NewBerTlvWriter()
	writer.WriteInteger(0x02, 256)
	expected = []byte{0x02, 0x02, 0x01, 0x00}
	result = writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestWriteConstructed(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteConstructed(0xA0, func(w *BerTlvWriter) {
		w.WritePrimitive(0x80, []byte{0x01, 0x02})
		w.WritePrimitive(0x81, []byte{0x03, 0x04, 0x05})
	})
	// Tag 0xA0, length 9 (4 + 5), then inner TLVs
	expected := []byte{0xA0, 0x09, 0x80, 0x02, 0x01, 0x02, 0x81, 0x03, 0x03, 0x04, 0x05}
	result := writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestWriteNumLength_Short(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteNumLength(10)
	expected := []byte{0x0A}
	result := writer.ToBytes()
	if len(result) != len(expected) || result[0] != expected[0] {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestWriteNumLength_Long(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteNumLength(256)
	expected := []byte{0x82, 0x01, 0x00}
	result := writer.ToBytes()
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], result[i])
		}
	}
}

func TestWriteTag(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteTag(0x80)
	expected := []byte{0x80}
	result := writer.ToBytes()
	if len(result) != 1 || result[0] != 0x80 {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestAsSlice(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WritePrimitive(0x80, []byte{0x01, 0x02, 0x03})
	slice := writer.AsSlice()
	if len(slice) != 5 {
		t.Errorf("expected 5 bytes, got %d", len(slice))
	}
}

// ============================================================================
// Roundtrip tests
// ============================================================================

func TestRoundtrip_Constructed(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteConstructed(0xA1, func(w *BerTlvWriter) {
		w.WritePrimitive(0x80, make([]byte, 65)) // public key
		w.WritePrimitive(0x81, make([]byte, 32)) // private key
		w.WritePrimitive(0x82, make([]byte, 32)) // chain code
	})

	bytes := writer.ToBytes()
	reader := NewBerTlvReader(bytes)
	length, err := reader.EnterConstructed(0xA1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedLen := uint32(1+1+65 + 1+1+32 + 1+1+32)
	if length != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, length)
	}

	pubKey, err := reader.ReadPrimitive(0x80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pubKey) != 65 {
		t.Errorf("expected pubKey length 65, got %d", len(pubKey))
	}

	privKey, err := reader.ReadPrimitive(0x81)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(privKey) != 32 {
		t.Errorf("expected privKey length 32, got %d", len(privKey))
	}

	chainCode, err := reader.ReadPrimitive(0x82)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chainCode) != 32 {
		t.Errorf("expected chainCode length 32, got %d", len(chainCode))
	}

	if len(reader.PeekUnread()) != 0 {
		t.Errorf("expected 0 unread bytes, got %d", len(reader.PeekUnread()))
	}
}

func TestRoundtrip_Boolean(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteBoolean(0x01, true)
	bytes := writer.ToBytes()

	reader := NewBerTlvReader(bytes)
	val, err := reader.ReadBoolean()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !val {
		t.Error("expected true")
	}
}

func TestRoundtrip_Integer(t *testing.T) {
	writer := NewBerTlvWriter()
	writer.WriteInteger(0x02, 12345)
	bytes := writer.ToBytes()

	reader := NewBerTlvReader(bytes)
	val, err := reader.ReadInteger()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 12345 {
		t.Errorf("expected 12345, got %d", val)
	}
}

func TestRoundtrip_EncodeDecodeBerLength(t *testing.T) {
	testValues := []uint32{0, 1, 10, 127, 128, 255, 256, 65535, 65536, 16777215, 16777216}
	for _, v := range testValues {
		encoded := EncodeBerLength(v)
		decoded, _, err := DecodeBerLength(encoded, 0)
		if err != nil {
			t.Errorf("DecodeBerLength failed for %d: %v", v, err)
			continue
		}
		if decoded != v {
			t.Errorf("roundtrip failed for %d: got %d", v, decoded)
		}
	}
}
