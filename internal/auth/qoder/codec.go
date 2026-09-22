package qoder

import "strings"

// BodyCodec implements the Qoder agent_chat_generation body codec (SOLVED and
// verified byte-exact against real captures; live E2E confirmed).
//
// Verified facts (see oauth-service/qorder/QODER_CODEC_FINAL.md and the live
// E2E probes in oauth-service/qorder/qoder_*):
//   - The body is NOT encrypted; it is custom-alphabet base64 of the plaintext.
//   - Alphabet (dumped from live Qoder.exe memory):
//       _doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
//   - Grouping is standard base64: every 4 chars = 24 bits = 3 plaintext bytes.
//   - '$' is an in-group pad character (RFC 4648 style): it is SKIPPED during
//     decode and does NOT contribute 6 bits. The 6-bit value 63 is encoded as
//     '!' (the alphabet's 64th char). Real captured bodies contain BOTH '$'
//     (as pad within groups) and '!' (as the value-63 data char). The single
//     '$' in qqtest appears in group 'exw$' — skipping it yields the correct
//     3 bytes; mapping it to 63 would produce an extra spurious byte (0x3F).
//   - Some bodies carry a 2-char magic prefix (e.g. "Qh" on records 68/88)
//     which must be dropped before group decode.
//   - Upstream server CustomBase64Util decode0 accepts these bodies (verified
//     live: replaying the real qqtest ciphertext through our COSY envelope
//     returned real SSE chat chunks).

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
// where k is the number of non-pad chars in the group. '$' is always skipped
// (RFC 4648 pad semantics); '!' encodes 6-bit value 63.
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

// BodyEncode encodes bytes into custom base64. 6-bit value 63 is emitted as
// '!' (the alphabet's 64th character). The final partial 6-bit group is
// zero-padded into one char; the char count is then padded to a multiple of 4
// with '$' pad chars.
func BodyEncode(data []byte) string {
	var sb strings.Builder
	acc := 0
	nb := 0
	for _, b := range data {
		acc = (acc << 8) | int(b)
		nb += 8
		for nb >= 6 {
			nb -= 6
			v := (acc >> nb) & 0x3F
			if v == BodyPadValue {
				sb.WriteByte('!')
			} else {
				sb.WriteByte(BodyAlphabet[v])
			}
		}
	}
	if nb > 0 {
		v := (acc << (6 - nb)) & 0x3F
		if v == BodyPadValue {
			sb.WriteByte('!')
		} else {
			sb.WriteByte(BodyAlphabet[v])
		}
	}
	for sb.Len()%4 != 0 {
		sb.WriteByte('$')
	}
	return sb.String()
}

// EncodeBody is the public encode entry point.
func EncodeBody(plaintext []byte) string {
	return BodyEncode(plaintext)
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
