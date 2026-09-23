package qoder

import "strings"

// BodyCodec implements the Qoder request body codec. The worker encodes the
// plaintext with this alphabet, then exchanges the first and last thirds of
// the encoded string.
//
// Verified facts:
//   - The captured alphabet and group/padding behavior are preserved here.
//   - Alphabet (dumped from live Qoder.exe memory):
//       _doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
//   - Grouping is standard base64: every 4 chars = 24 bits = 3 plaintext bytes.
//   - '!' (alphabet 64th char) encodes 6-bit value 63.
//   - A single plaintext request is encoded as one continuous base64 stream.

const (
	// BodyAlphabet is the custom base64 alphabet.
	BodyAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	// BodyPad is the pad character that occupies a slot but contributes no data.
	BodyPad = "$"
	// BodyExclamation is the data character encoding 6-bit value 63.
	BodyExclamation = "!"
	// BodyPadValue is the 6-bit value represented by '!' (BodyExclamation).
	BodyPadValue = 63
)

var bodyAlphabetIndex = func() [256]int8 {
	var m [256]int8
	for i := range m {
		m[i] = -1
	}
	for i, c := range BodyAlphabet {
		m[c] = int8(i)
	}
	return m
}()

// groupBytes decodes one 4-char group to its N bytes, where N = floor(6*k/8)
// and k = number of non-pad chars in the group. '$' is skipped; '!' maps to 63.
func groupBytes(grp string) []byte {
	var vals []int
	for _, c := range grp {
		if c == '$' {
			continue
		}
		if c == '!' {
			vals = append(vals, BodyPadValue)
		} else {
			vals = append(vals, int(bodyAlphabetIndex[c]))
		}
	}
	nv := len(vals)
	if nv == 0 {
		return nil
	}
	x := 0
	for _, v := range vals {
		x = (x << 6) | v
	}
	nb := (6 * nv) / 8
	out := make([]byte, nb)
	for k := 0; k < nb; k++ {
		sh := 6*nv - 8*(k+1)
		out[k] = byte((x >> sh) & 255)
	}
	return out
}

// BodyDecode decodes a body: each 4-char group yields floor(6*k/8) bytes,
// where k is the number of non-pad chars in the group. '$' is skipped, '!'
// encodes 6-bit value 63.
func BodyDecode(s string) []byte {
	var out []byte
	for gi := 0; gi+4 <= len(s); gi += 4 {
		b := groupBytes(s[gi : gi+4])
		if b != nil {
			out = append(out, b...)
		}
	}
	return out
}

// segmentEncode encodes one segment with standard base64 bitstream: bytes to
// 6-bit groups (MSB first), mapped through the custom alphabet; final partial
// group zero-padded into one char; char count padded to multiple of 4 with '$'.
// 6-bit value 63 is emitted as '!'.
func segmentEncode(data []byte) string {
	var sb strings.Builder
	acc := 0
	nb := 0
	emit := func(v int) {
		if v == BodyPadValue {
			sb.WriteByte('!')
		} else {
			sb.WriteByte(BodyAlphabet[v])
		}
	}
	for _, b := range data {
		acc = (acc << 8) | int(b)
		nb += 8
		for nb >= 6 {
			nb -= 6
			emit((acc >> nb) & 0x3F)
		}
	}
	if nb > 0 {
		emit((acc << (6 - nb)) & 0x3F)
	}
	for sb.Len()%4 != 0 {
		sb.WriteByte('$')
	}
	return sb.String()
}

// BodyEncode encodes one plaintext request into custom base64.
func BodyEncode(data []byte) string {
	return segmentEncode(data)
}

// EncodeBody is the public encode entry point.
func EncodeBody(plaintext []byte) string {
	return BodyEncode(plaintext)
}

// EncodeRequestBody produces the wire body used by prepareInferRequest in the
// Qoder worker. The middle segment remains in place when the outer thirds swap.
func EncodeRequestBody(plaintext []byte) string {
	return swapBodyOuterThirds(BodyEncode(plaintext))
}

// DecodeRequestBody reverses the wire-body permutation before base64 decoding.
func DecodeRequestBody(wire string) []byte {
	return BodyDecode(swapBodyOuterThirds(wire))
}

func swapBodyOuterThirds(encoded string) string {
	third := len(encoded) / 3
	if third == 0 {
		return encoded
	}
	return encoded[len(encoded)-third:] + encoded[third:len(encoded)-third] + encoded[:third]
}

// EncodeBodySegments encodes multiple plaintext segments joined by '$'.
func EncodeBodySegments(plaintexts ...[]byte) string {
	parts := make([]string, 0, len(plaintexts))
	for _, p := range plaintexts {
		parts = append(parts, BodyEncode(p))
	}
	return strings.Join(parts, BodyPad)
}

// DecodeBody decodes a whole body (group-wise; '$' = pad/skip, '!' = value 63).
func DecodeBody(cipherB64 string) []byte {
	return BodyDecode(cipherB64)
}
