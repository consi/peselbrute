package main

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeka/zip"
)

var crc32Tab [256]uint32
var rc4Init [256]byte

var (
	mul3 = [10]int{0, 3, 6, 9, 2, 5, 8, 1, 4, 7}
	mul7 = [10]int{0, 7, 4, 1, 8, 5, 2, 9, 6, 3}
	mul9 = [10]int{0, 9, 8, 7, 6, 5, 4, 3, 2, 1}
)

func init() {
	for i := range crc32Tab {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = (c >> 1) ^ 0xedb88320
			} else {
				c >>= 1
			}
		}
		crc32Tab[i] = c
	}
	for i := range rc4Init {
		rc4Init[i] = byte(i)
	}
}

func formatCount(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fG", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return strconv.FormatInt(n, 10)
	}
}

func formatRate(perSec float64) string {
	switch {
	case perSec >= 1e9:
		return fmt.Sprintf("%.1fG/s", perSec/1e9)
	case perSec >= 1e6:
		return fmt.Sprintf("%.1fM/s", perSec/1e6)
	case perSec >= 1e3:
		return fmt.Sprintf("%.1fk/s", perSec/1e3)
	default:
		return fmt.Sprintf("%.1f/s", perSec)
	}
}

// zipCryptoDecryptor decrypts ZipCrypto-encrypted data using a running key state.
// Implements io.Reader so it can feed directly into compress/flate.
type zipCryptoDecryptor struct {
	src        []byte
	pos        int
	k0, k1, k2 uint32
}

func (d *zipCryptoDecryptor) Read(p []byte) (int, error) {
	avail := len(d.src) - d.pos
	if avail <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > avail {
		n = avail
	}
	for i := 0; i < n; i++ {
		temp := d.k2 | 2
		p[i] = d.src[d.pos] ^ byte((temp*(temp^1))>>8)
		d.k0 = crc32Tab[(d.k0^uint32(p[i]))&0xff] ^ (d.k0 >> 8)
		d.k1 = (d.k1+(d.k0&0xff))*0x08088405 + 1
		d.k2 = crc32Tab[(d.k2^(d.k1>>24))&0xff] ^ (d.k2 >> 8)
		d.pos++
	}
	return n, nil
}

func (d *zipCryptoDecryptor) reset(k0, k1, k2 uint32) {
	d.pos = 0
	d.k0, d.k1, d.k2 = k0, k1, k2
}

type dateTask struct {
	year, month, day int
}

type zipTarget struct {
	encHeader   [12]byte
	crcCheck    byte
	timeCheck   byte
	compData    []byte // compressed payload (after 12-byte encryption header)
	expectedCRC uint32
}

type fileKind int

const (
	fileKindUnknown fileKind = iota
	fileKindZIP
	fileKindPDF
)

type sexFilter int

const (
	sexAll    sexFilter = iota
	sexMale             // PESEL digit 10 is odd
	sexFemale           // PESEL digit 10 is even
)

type pdfTarget struct {
	r               int
	keyLen          int
	o               []byte
	u               []byte
	p               int32
	id0             []byte
	encryptMetadata bool
}

type pdfVerifier struct {
	r        int
	keyLen   int
	baseTail []byte
	u        [32]byte
	uSeed16  [16]byte
	uValSalt [8]byte // for R>=5: u[32:40] validation salt
}

type pdfVerifyState struct {
	base   []byte
	key    [16]byte
	out32  [32]byte
	out16  [16]byte
	// Pre-allocated buffers for R=6 iterative hash (allocation-free hot path)
	r6plain []byte // 64 * (passLen + 32 + udataLen) — reused every iteration
}

var (
	pdfPasswordPad = [32]byte{
		0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
		0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
		0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
		0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
	}

	rePDFTrailerEncryptRef = regexp.MustCompile(`/Encrypt\s+(\d+)\s+(\d+)\s+R`)
	rePDFTrailerID         = regexp.MustCompile(`/ID\s*\[\s*<([0-9A-Fa-f\s]+)>`)
	rePDFR                 = regexp.MustCompile(`/R\s+(-?\d+)`)
	rePDFLength            = regexp.MustCompile(`/Length\s+(-?\d+)`)
	rePDFP                 = regexp.MustCompile(`/P\s+(-?\d+)`)
	rePDFO                 = regexp.MustCompile(`/O\s*(<[^>]*>|\([^)]*\))`)
	rePDFU                 = regexp.MustCompile(`/U\s*(<[^>]*>|\([^)]*\))`)
	rePDFFilterStandard    = regexp.MustCompile(`/Filter\s*/Standard\b`)
	rePDFEncryptMetadata   = regexp.MustCompile(`/EncryptMetadata\s+(true|false)\b`)
)

func detectFileKind(data []byte) fileKind {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}) {
		return fileKindZIP
	}
	limit := len(data)
	if limit > 1024 {
		limit = 1024
	}
	for i := 0; i+5 <= limit; i++ {
		if data[i] == '%' && bytes.Equal(data[i:i+5], []byte("%PDF-")) {
			return fileKindPDF
		}
		if data[i] > 0x20 {
			break
		}
	}
	return fileKindUnknown
}

func parsePDFTarget(data []byte) (*pdfTarget, error) {
	trailerIdx := bytes.LastIndex(data, []byte("trailer"))
	if trailerIdx < 0 {
		return nil, errors.New("PDF trailer not found")
	}
	dictStart := bytes.Index(data[trailerIdx:], []byte("<<"))
	if dictStart < 0 {
		return nil, errors.New("PDF trailer dictionary missing")
	}
	dictStart += trailerIdx
	trailerDict, _, err := parsePDFDictAt(data, dictStart)
	if err != nil {
		return nil, fmt.Errorf("invalid PDF trailer dictionary: %w", err)
	}

	encRef := rePDFTrailerEncryptRef.FindSubmatch(trailerDict)
	if len(encRef) != 3 {
		return nil, errors.New("PDF Encrypt reference not found in trailer")
	}
	objNum, err := strconv.Atoi(string(encRef[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid PDF Encrypt object number: %w", err)
	}
	if string(encRef[2]) != "0" {
		return nil, errors.New("unsupported PDF Encrypt generation (only 0 supported)")
	}

	var id0 []byte
	idMatch := rePDFTrailerID.FindSubmatch(trailerDict)
	if len(idMatch) == 2 {
		id0Hex := compactHexSpaces(string(idMatch[1]))
		id0, err = hex.DecodeString(id0Hex)
		if err != nil {
			return nil, fmt.Errorf("invalid PDF trailer ID[0]: %w", err)
		}
	}

	encDict, err := findPDFObjectDict(data, objNum)
	if err != nil {
		return nil, err
	}
	if !rePDFFilterStandard.Match(encDict) {
		return nil, errors.New("unsupported PDF encryption filter (only /Standard)")
	}

	r, err := extractPDFInt(encDict, rePDFR, "R")
	if err == nil && r < 5 && id0 == nil {
		return nil, errors.New("PDF trailer /ID[0] is required for R<5")
	}
	if err != nil {
		return nil, err
	}
	if r < 2 || r > 6 {
		return nil, fmt.Errorf("unsupported PDF revision R=%d (supported: 2-6)", r)
	}

	keyBits, err := extractPDFInt(encDict, rePDFLength, "Length")
	if err != nil {
		if r == 2 {
			keyBits = 40
		} else if r >= 5 {
			keyBits = 256
		} else {
			return nil, err
		}
	}
	keyLen := keyBits / 8
	if r >= 5 {
		// Some PDFs store Length in bytes (e.g. 32 for AES-256); treat 32 as 256 bits
		if keyBits == 32 && keyLen == 4 {
			keyBits = 256
			keyLen = 32
		}
		if keyLen != 16 && keyLen != 32 {
			return nil, fmt.Errorf("unsupported PDF key length for R>=5: %d bits", keyBits)
		}
	} else if keyLen < 5 || keyLen > 16 {
		return nil, fmt.Errorf("unsupported PDF key length: %d bits", keyBits)
	}

	pVal, err := extractPDFInt(encDict, rePDFP, "P")
	if err != nil {
		return nil, err
	}

	o, err := extractPDFStringValue(encDict, rePDFO, "O")
	if err != nil {
		return nil, err
	}
	u, err := extractPDFStringValue(encDict, rePDFU, "U")
	if err != nil {
		return nil, err
	}
	uLen := 32
	oLen := 32
	if r >= 5 {
		uLen = 48
		oLen = 48
	}
	if len(o) < oLen || len(u) < uLen {
		return nil, errors.New("invalid PDF O/U entries")
	}

	encryptMetadata := true
	if m := rePDFEncryptMetadata.FindSubmatch(encDict); len(m) == 2 {
		encryptMetadata = strings.EqualFold(string(m[1]), "true")
	}

	return &pdfTarget{
		r:               r,
		keyLen:          keyLen,
		o:               o[:oLen],
		u:               u[:uLen],
		p:               int32(pVal),
		id0:             id0,
		encryptMetadata: encryptMetadata,
	}, nil
}

func parsePDFDictAt(data []byte, start int) ([]byte, int, error) {
	if start < 0 || start+1 >= len(data) || data[start] != '<' || data[start+1] != '<' {
		return nil, 0, errors.New("dictionary start not found")
	}
	depth := 0
	i := start
	for i+1 < len(data) {
		if data[i] == '<' && data[i+1] == '<' {
			depth++
			i += 2
			continue
		}
		if data[i] == '>' && data[i+1] == '>' {
			depth--
			i += 2
			if depth == 0 {
				return data[start:i], i, nil
			}
			continue
		}
		i++
	}
	return nil, 0, errors.New("unterminated dictionary")
}

func findPDFObjectDict(data []byte, objNum int) ([]byte, error) {
	pat := []byte(strconv.Itoa(objNum) + " 0 obj")
	idx := bytes.Index(data, pat)
	if idx < 0 {
		return nil, fmt.Errorf("PDF object %d 0 obj not found", objNum)
	}
	dictStart := bytes.Index(data[idx+len(pat):], []byte("<<"))
	if dictStart < 0 {
		return nil, fmt.Errorf("PDF object %d dictionary not found", objNum)
	}
	dictStart += idx + len(pat)
	dict, _, err := parsePDFDictAt(data, dictStart)
	if err != nil {
		return nil, fmt.Errorf("invalid PDF object %d dictionary: %w", objNum, err)
	}
	return dict, nil
}

func compactHexSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' {
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()
	if len(out)%2 == 1 {
		return out + "0"
	}
	return out
}

func extractPDFInt(dict []byte, re *regexp.Regexp, key string) (int, error) {
	m := re.FindSubmatch(dict)
	if len(m) != 2 {
		return 0, fmt.Errorf("PDF encryption key /%s missing", key)
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, fmt.Errorf("PDF encryption key /%s invalid: %w", key, err)
	}
	return v, nil
}

func extractPDFStringValue(dict []byte, re *regexp.Regexp, key string) ([]byte, error) {
	m := re.FindSubmatch(dict)
	if len(m) != 2 {
		return nil, fmt.Errorf("PDF encryption key /%s missing", key)
	}
	return decodePDFStringToken(string(m[1]))
}

func decodePDFStringToken(tok string) ([]byte, error) {
	tok = strings.TrimSpace(tok)
	if len(tok) < 2 {
		return nil, errors.New("invalid PDF string token")
	}
	if tok[0] == '<' && tok[len(tok)-1] == '>' {
		return hex.DecodeString(compactHexSpaces(tok[1 : len(tok)-1]))
	}
	if tok[0] == '(' && tok[len(tok)-1] == ')' {
		src := tok[1 : len(tok)-1]
		out := make([]byte, 0, len(src))
		for i := 0; i < len(src); i++ {
			c := src[i]
			if c != '\\' {
				out = append(out, c)
				continue
			}
			i++
			if i >= len(src) {
				break
			}
			switch src[i] {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\\', '(', ')':
				out = append(out, src[i])
			case '\n', '\r':
				// line continuation
			default:
				if src[i] >= '0' && src[i] <= '7' {
					val := int(src[i] - '0')
					for j := 0; j < 2 && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '7'; j++ {
						i++
						val = (val << 3) + int(src[i]-'0')
					}
					out = append(out, byte(val))
				} else {
					out = append(out, src[i])
				}
			}
		}
		return out, nil
	}
	return nil, errors.New("unsupported PDF string format")
}

func padPDFPassword(pass []byte) [32]byte {
	var out [32]byte
	n := len(pass)
	if n > 32 {
		n = 32
	}
	copy(out[:], pass[:n])
	if n < 32 {
		copy(out[n:], pdfPasswordPad[:32-n])
	}
	return out
}

// pdfHashR5 computes SHA-256(password + salt + udata) for R=5 user password verification.
func pdfHashR5(password, salt, udata []byte) [32]byte {
	h := sha256.New()
	h.Write(password)
	h.Write(salt)
	h.Write(udata)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// pdfHashR6 computes the R=6 iterative hash (ISO 32000-2, Algorithm 2.B).
// K is variable-length: 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512) bytes.
// plainBuf must be pre-allocated with at least 64*(len(password)+64+len(udata)) bytes.
func pdfHashR6(password, salt, udata, plainBuf []byte) [32]byte {
	k256 := pdfHashR5(password, salt, udata)
	var kBuf [64]byte
	copy(kBuf[:], k256[:])
	kLen := 32

	// ISO 32000-2 (Algorithm 2.B): run at least 64 rounds (i=0..63),
	// then stop when the last byte of E is <= i-32.
	// The termination check uses the PREVIOUS round's E, so we save
	// its last byte and check BEFORE computing the next round.
	var lastE byte
	for round := 0; ; round++ {
		if round >= 64 && int(lastE) <= round-32 {
			break
		}

		k1Len := len(password) + kLen + len(udata)
		plainLen := k1Len * 64
		plain := plainBuf[:plainLen]

		off := 0
		copy(plain[off:], password)
		off += len(password)
		copy(plain[off:], kBuf[:kLen])
		off += kLen
		copy(plain[off:], udata)
		for i := 1; i < 64; i++ {
			copy(plain[i*k1Len:], plain[:k1Len])
		}

		block, _ := aes.NewCipher(kBuf[:16])
		cipher.NewCBCEncrypter(block, kBuf[16:32]).CryptBlocks(plain, plain)

		lastE = plain[plainLen-1]

		s := 0
		for _, b := range plain[:16] {
			s += int(b)
		}
		switch s % 3 {
		case 0:
			h := sha256.Sum256(plain)
			copy(kBuf[:], h[:])
			kLen = 32
		case 1:
			h := sha512.Sum384(plain)
			copy(kBuf[:], h[:])
			kLen = 48
		default:
			h := sha512.Sum512(plain)
			copy(kBuf[:], h[:])
			kLen = 64
		}
	}
	var out [32]byte
	copy(out[:], kBuf[:32])
	return out
}

func (t *pdfTarget) verifyPassword(pass []byte) bool {
	if t.r >= 5 {
		if len(pass) > 127 {
			pass = pass[:127]
		}
		if t.r == 5 {
			h := pdfHashR5(pass, t.u[32:40], nil)
			return bytes.Equal(h[:], t.u[:32])
		}
		plainBuf := make([]byte, 64*(len(pass)+64))
		h := pdfHashR6(pass, t.u[32:40], nil, plainBuf)
		return bytes.Equal(h[:], t.u[:32])
	}
	padded := padPDFPassword(pass)

	need := 32 + len(t.o) + 4 + len(t.id0) + 4
	var baseArr [256]byte
	base := baseArr[:0]
	if need > len(baseArr) {
		base = make([]byte, 0, need)
	}
	base = append(base, padded[:]...)
	base = append(base, t.o...)
	var pLE [4]byte
	binary.LittleEndian.PutUint32(pLE[:], uint32(t.p))
	base = append(base, pLE[:]...)
	base = append(base, t.id0...)
	if t.r >= 4 && !t.encryptMetadata {
		base = append(base, 0xff, 0xff, 0xff, 0xff)
	}

	sum := md5.Sum(base)
	var key [16]byte
	keySlice := key[:t.keyLen]
	copy(keySlice, sum[:t.keyLen])
	if t.r >= 3 {
		for i := 0; i < 50; i++ {
			sum = md5.Sum(keySlice)
			copy(keySlice, sum[:t.keyLen])
		}
	}

	if t.r == 2 {
		var out [32]byte
		copy(out[:], pdfPasswordPad[:])
		rc4XORKeyStream(keySlice, out[:])
		return bytes.Equal(out[:], t.u)
	}

	var vArr [96]byte
	v := vArr[:32+len(t.id0)]
	if len(v) > len(vArr) {
		v = make([]byte, 32+len(t.id0))
	}
	copy(v[:32], pdfPasswordPad[:])
	copy(v[32:], t.id0)
	uHash := md5.Sum(v)
	var out [16]byte
	copy(out[:], uHash[:16])
	var tmpKey [16]byte
	for i := 0; i < 20; i++ {
		for j := 0; j < len(keySlice); j++ {
			tmpKey[j] = keySlice[j] ^ byte(i)
		}
		rc4XORKeyStream(tmpKey[:len(keySlice)], out[:])
	}
	return bytes.Equal(out[:], t.u[:16])
}

func newPDFVerifier(t *pdfTarget) *pdfVerifier {
	baseTail := make([]byte, 0, len(t.o)+4+len(t.id0)+4)
	baseTail = append(baseTail, t.o...)
	var pLE [4]byte
	binary.LittleEndian.PutUint32(pLE[:], uint32(t.p))
	baseTail = append(baseTail, pLE[:]...)
	baseTail = append(baseTail, t.id0...)
	if t.r >= 4 && !t.encryptMetadata {
		baseTail = append(baseTail, 0xff, 0xff, 0xff, 0xff)
	}

	v := &pdfVerifier{
		r:        t.r,
		keyLen:   t.keyLen,
		baseTail: baseTail,
	}
	copy(v.u[:], t.u[:32])
	if t.r >= 5 && len(t.u) >= 48 {
		copy(v.uValSalt[:], t.u[32:40])
	}

	if t.r >= 3 && t.r < 5 {
		seedLen := 32 + len(t.id0)
		var seedArr [96]byte
		seed := seedArr[:seedLen]
		if seedLen > len(seedArr) {
			seed = make([]byte, seedLen)
		}
		copy(seed[:32], pdfPasswordPad[:])
		copy(seed[32:], t.id0)
		uHash := md5.Sum(seed)
		copy(v.uSeed16[:], uHash[:16])
	}

	return v
}

func newPDFVerifyState(v *pdfVerifier) *pdfVerifyState {
	st := &pdfVerifyState{
		base: make([]byte, 32+len(v.baseTail)),
	}
	copy(st.base[11:32], pdfPasswordPad[:21])
	copy(st.base[32:], v.baseTail)
	if v.r >= 6 {
		// Pre-allocate buffer for R=6: max K is 64 bytes (SHA-512), so 64 * (11 + 64) = 4800
		st.r6plain = make([]byte, 64*(11+64))
	}
	return st
}

func (v *pdfVerifier) verifyPass11(pass *[11]byte, st *pdfVerifyState) bool {
	if v.r == 5 {
		// R=5: SHA-256(password[11] + valSalt[8]) — zero allocation
		var buf [19]byte
		copy(buf[:11], pass[:])
		copy(buf[11:], v.uValSalt[:])
		return sha256.Sum256(buf[:]) == v.u
	}
	if v.r >= 6 {
		h := pdfHashR6(pass[:], v.uValSalt[:], nil, st.r6plain)
		return h == v.u
	}
	copy(st.base[:11], pass[:])

	sum := md5.Sum(st.base)
	keySlice := st.key[:v.keyLen]
	copy(keySlice, sum[:v.keyLen])
	if v.r >= 3 {
		for i := 0; i < 50; i++ {
			sum = md5.Sum(keySlice)
			copy(keySlice, sum[:v.keyLen])
		}
	}

	if v.r == 2 {
		copy(st.out32[:], pdfPasswordPad[:])
		rc4XORKeyStream(keySlice, st.out32[:])
		return bytes.Equal(st.out32[:], v.u[:])
	}

	copy(st.out16[:], v.uSeed16[:])
	for i := 0; i < 20; i++ {
		rc4XORKeyStreamKeyXor(keySlice, byte(i), st.out16[:])
	}
	return bytes.Equal(st.out16[:], v.u[:16])
}

func rc4XORKeyStream(key, data []byte) {
	if len(key) == 0 || len(data) == 0 {
		return
	}

	var s [256]byte
	copy(s[:], rc4Init[:])

	var j uint8
	keyLen := len(key)
	ki := 0
	for i := 0; i < 256; i++ {
		j += s[i] + key[ki]
		s[i], s[j] = s[j], s[i]
		ki++
		if ki == keyLen {
			ki = 0
		}
	}

	var i, k uint8
	for idx := 0; idx < len(data); idx++ {
		i++
		k += s[i]
		s[i], s[k] = s[k], s[i]
		data[idx] ^= s[s[i]+s[k]]
	}
}

func rc4XORKeyStreamKeyXor(key []byte, keyXor byte, data []byte) {
	if len(key) == 0 || len(data) == 0 {
		return
	}

	var s [256]byte
	copy(s[:], rc4Init[:])

	var j uint8
	keyLen := len(key)
	ki := 0
	for i := 0; i < 256; i++ {
		j += s[i] + (key[ki] ^ keyXor)
		s[i], s[j] = s[j], s[i]
		ki++
		if ki == keyLen {
			ki = 0
		}
	}

	var i, k uint8
	for idx := 0; idx < len(data); idx++ {
		i++
		k += s[i]
		s[i], s[k] = s[k], s[i]
		data[idx] ^= s[s[i]+s[k]]
	}
}

func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}

func peselMonthCode(y, m int) int {
	if y >= 2000 {
		return m + 20
	}
	return m
}

func generateDates(ch chan<- dateTask, found *atomic.Bool, startY, startM, startD, endY, endM, endD int) {
	defer close(ch)

	startT := time.Date(startY, time.Month(startM), startD, 0, 0, 0, 0, time.UTC)
	endT := time.Date(endY, time.Month(endM), endD, 0, 0, 0, 0, time.UTC)
	midT := startT.Add(endT.Sub(startT) / 2)

	fy, fm, fd := midT.Year(), int(midT.Month()), midT.Day()
	by, bm, bd := fy, fm, fd

	next := func(y, m, d int) (int, int, int) {
		d++
		if d > daysInMonth(y, m) {
			d = 1
			m++
			if m > 12 {
				m = 1
				y++
			}
		}
		return y, m, d
	}

	prev := func(y, m, d int) (int, int, int) {
		d--
		if d < 1 {
			m--
			if m < 1 {
				m = 12
				y--
			}
			d = daysInMonth(y, m)
		}
		return y, m, d
	}

	by, bm, bd = prev(by, bm, bd)

	fDone, bDone := false, false
	for !fDone || !bDone {
		if found.Load() {
			return
		}
		if !fDone {
			if fy > endY || (fy == endY && fm > endM) || (fy == endY && fm == endM && fd > endD) {
				fDone = true
			} else {
				ch <- dateTask{fy, fm, fd}
				fy, fm, fd = next(fy, fm, fd)
			}
		}
		if found.Load() {
			return
		}
		if !bDone {
			if by < startY || (by == startY && bm < startM) || (by == startY && bm == startM && bd < startD) {
				bDone = true
			} else {
				ch <- dateTask{by, bm, bd}
				by, bm, bd = prev(by, bm, bd)
			}
		}
	}
}

func zipCryptoPrecompute(dateBytes [6]byte) (k0, k1, k2 uint32) {
	k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
	for i := 0; i < 6; i++ {
		k0 = crc32Tab[(k0^uint32(dateBytes[i]))&0xff] ^ (k0 >> 8)
		k1 = (k1+(k0&0xff))*0x08088405 + 1
		k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
	}
	return
}

func fastWorker(
	target *zipTarget,
	ch <-chan dateTask, found *atomic.Bool, counter *atomic.Int64, resultCh chan<- string,
	sex sexFilter,
) {
	dec := &zipCryptoDecryptor{src: target.compData}
	fr := flate.NewReader(bytes.NewReader([]byte{0})) // dummy init
	resetter := fr.(flate.Resetter)
	crcW := crc32.NewIEEE()
	copyBuf := make([]byte, 32*1024)
	perDay := int64(10000)
	if sex != sexAll {
		perDay = 5000
	}

	for task := range ch {
		if found.Load() {
			return
		}

		yy := task.year % 100
		mc := peselMonthCode(task.year, task.month)
		dd := [6]int{yy / 10, yy % 10, mc / 10, mc % 10, task.day / 10, task.day % 10}
		db := [6]byte{byte('0' + dd[0]), byte('0' + dd[1]), byte('0' + dd[2]), byte('0' + dd[3]), byte('0' + dd[4]), byte('0' + dd[5])}
		pk0, pk1, pk2 := zipCryptoPrecompute(db)
		partW := dd[0] + mul3[dd[1]] + mul7[dd[2]] + mul9[dd[3]] + dd[4] + mul3[dd[5]]

		for serial := 0; serial < 10000; serial++ {
			s3 := serial / 1000
			s2 := (serial / 100) % 10
			s1 := (serial / 10) % 10
			s0 := serial % 10

			if sex == sexMale && s0%2 == 0 {
				continue
			}
			if sex == sexFemale && s0%2 != 0 {
				continue
			}

			wsum := partW + mul7[s3] + mul9[s2] + s1 + mul3[s0]
			cd := (10 - wsum%10) % 10

			sb := [5]byte{byte('0' + s3), byte('0' + s2), byte('0' + s1), byte('0' + s0), byte('0' + cd)}

			k0, k1, k2 := pk0, pk1, pk2
			for i := 0; i < 5; i++ {
				k0 = crc32Tab[(k0^uint32(sb[i]))&0xff] ^ (k0 >> 8)
				k1 = (k1+(k0&0xff))*0x08088405 + 1
				k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
			}

			var last byte
			for i := 0; i < 12; i++ {
				temp := k2 | 2
				last = target.encHeader[i] ^ byte((temp*(temp^1))>>8)
				k0 = crc32Tab[(k0^uint32(last))&0xff] ^ (k0 >> 8)
				k1 = (k1+(k0&0xff))*0x08088405 + 1
				k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
			}

			if last != target.crcCheck && last != target.timeCheck {
				continue
			}

			// Header check passed — verify by decrypting+decompressing+CRC
			dec.reset(k0, k1, k2)
			resetter.Reset(dec, nil)
			crcW.Reset()

			_, err := io.CopyBuffer(crcW, fr, copyBuf)
			if err != nil {
				continue
			}
			if crcW.Sum32() != target.expectedCRC {
				continue
			}

			var pesel [11]byte
			copy(pesel[:6], db[:])
			copy(pesel[6:], sb[:])
			if found.CompareAndSwap(false, true) {
				resultCh <- string(pesel[:])
			}
			return
		}
		counter.Add(perDay)
	}
}

func libWorker(
	zipData []byte,
	ch <-chan dateTask, found *atomic.Bool, counter *atomic.Int64, resultCh chan<- string,
	sex sexFilter,
) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return
	}
	var zf *zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() {
			zf = f
			break
		}
	}
	if zf == nil {
		return
	}
	probe := make([]byte, 128)
	perDay := int64(10000)
	if sex != sexAll {
		perDay = 5000
	}

	for task := range ch {
		if found.Load() {
			return
		}

		yy := task.year % 100
		mc := peselMonthCode(task.year, task.month)
		dd := [6]int{yy / 10, yy % 10, mc / 10, mc % 10, task.day / 10, task.day % 10}
		partW := dd[0] + mul3[dd[1]] + mul7[dd[2]] + mul9[dd[3]] + dd[4] + mul3[dd[5]]

		var pesel [11]byte
		for i := 0; i < 6; i++ {
			pesel[i] = byte('0' + dd[i])
		}

		for serial := 0; serial < 10000; serial++ {
			s3 := serial / 1000
			s2 := (serial / 100) % 10
			s1 := (serial / 10) % 10
			s0 := serial % 10

			if sex == sexMale && s0%2 == 0 {
				continue
			}
			if sex == sexFemale && s0%2 != 0 {
				continue
			}

			wsum := partW + mul7[s3] + mul9[s2] + s1 + mul3[s0]
			cd := (10 - wsum%10) % 10

			pesel[6] = byte('0' + s3)
			pesel[7] = byte('0' + s2)
			pesel[8] = byte('0' + s1)
			pesel[9] = byte('0' + s0)
			pesel[10] = byte('0' + cd)

			password := string(pesel[:])
			zf.SetPassword(password)
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			_, err = io.ReadFull(rc, probe)
			if err != nil {
				rc.Close()
				continue
			}
			_, err = io.Copy(io.Discard, rc)
			rc.Close()
			if err == nil {
				if found.CompareAndSwap(false, true) {
					resultCh <- password
				}
				return
			}
		}
		counter.Add(perDay)
	}
}

func pdfWorker(
	target *pdfTarget,
	ch <-chan dateTask, found *atomic.Bool, counter *atomic.Int64, resultCh chan<- string,
	sex sexFilter,
) {
	verifier := newPDFVerifier(target)
	state := newPDFVerifyState(verifier)
	slowPath := target.r >= 5
	perDay := int64(10000)
	if sex != sexAll {
		perDay = 5000
	}

	for task := range ch {
		if found.Load() {
			return
		}

		yy := task.year % 100
		mc := peselMonthCode(task.year, task.month)
		dd := [6]int{yy / 10, yy % 10, mc / 10, mc % 10, task.day / 10, task.day % 10}
		partW := dd[0] + mul3[dd[1]] + mul7[dd[2]] + mul9[dd[3]] + dd[4] + mul3[dd[5]]

		var pesel [11]byte
		for i := 0; i < 6; i++ {
			pesel[i] = byte('0' + dd[i])
		}

		// R>=5 is slow enough that atomics per candidate can matter; batch increments.
		// This also keeps "Checked" accurate (previous logic accidentally double-counted).
		var pending int64
		for s3 := 0; s3 < 10; s3++ {
			pesel[6] = byte('0' + s3)
			p3 := partW + mul7[s3]
			for s2 := 0; s2 < 10; s2++ {
				pesel[7] = byte('0' + s2)
				p2 := p3 + mul9[s2]
				for s1 := 0; s1 < 10; s1++ {
					pesel[8] = byte('0' + s1)
					p1 := p2 + s1
					for s0 := 0; s0 < 10; s0++ {
						if sex == sexMale && s0%2 == 0 {
							continue
						}
						if sex == sexFemale && s0%2 != 0 {
							continue
						}
						pesel[9] = byte('0' + s0)
						wsum := p1 + mul3[s0]
						cd := (10 - wsum%10) % 10
						pesel[10] = byte('0' + cd)

						if slowPath {
							pending++
							if pending >= 512 {
								counter.Add(pending)
								pending = 0
							}
						}
						if !verifier.verifyPass11(&pesel, state) {
							continue
						}
						if slowPath && pending > 0 {
							counter.Add(pending)
							pending = 0
						}
						if found.CompareAndSwap(false, true) {
							resultCh <- string(pesel[:])
						}
						return
					}
				}
			}
		}
		if slowPath {
			if pending > 0 {
				counter.Add(pending)
			}
		} else {
			counter.Add(perDay)
		}
	}
}

func main() {
	benchDur := flag.Duration("bench", 0, "benchmark mode: run for duration and exit (e.g. 5s, 1m)")
	workers := flag.Int("workers", runtime.NumCPU(), "number of parallel workers")
	fromDate := flag.String("from", "1900-01-01", "start of birth date range (YYYY-MM-DD)")
	toDate := flag.String("to", "", "end of birth date range (YYYY-MM-DD, default today)")
	sexFlag := flag.String("sex", "", "filter by sex: m (male) or f (female)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <file.{zip|pdf}>\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Parse sex filter
	var sex sexFilter
	switch strings.ToLower(*sexFlag) {
	case "":
		sex = sexAll
	case "m", "male":
		sex = sexMale
	case "f", "female":
		sex = sexFemale
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid -sex value %q (use 'm' or 'f')\n", *sexFlag)
		os.Exit(1)
	}

	// Parse date range
	fromTime, err := time.Parse("2006-01-02", *fromDate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid -from date %q (use YYYY-MM-DD)\n", *fromDate)
		os.Exit(1)
	}
	fromY, fromM, fromD := fromTime.Year(), int(fromTime.Month()), fromTime.Day()

	var toY, toM, toD int
	if *toDate == "" {
		now := time.Now()
		toY, toM, toD = now.Year(), int(now.Month()), now.Day()
	} else {
		toTime, err := time.Parse("2006-01-02", *toDate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid -to date %q (use YYYY-MM-DD)\n", *toDate)
			os.Exit(1)
		}
		toY, toM, toD = toTime.Year(), int(toTime.Month()), toTime.Day()
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	path := flag.Arg(0)

	fileData, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	kind := detectFileKind(fileData)
	var pdfT *pdfTarget
	var target *zipTarget
	mode := ""

	switch kind {
	case fileKindZIP:
		zr, err := zip.NewReader(bytes.NewReader(fileData), int64(len(fileData)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid ZIP: %v\n", err)
			os.Exit(1)
		}
		if len(zr.File) == 0 {
			fmt.Fprintln(os.Stderr, "ZIP has no entries")
			os.Exit(1)
		}

		fmt.Printf("File:    %s (ZIP, %d entries)\n", path, len(zr.File))
		for _, f := range zr.File {
			if !f.FileInfo().IsDir() {
				fmt.Printf("Entry:   %s (%d bytes)\n", f.Name, f.UncompressedSize64)
				break
			}
		}

		// Parse local file header for fast ZipCrypto path.
		if len(fileData) >= 30 && binary.LittleEndian.Uint32(fileData[0:4]) == 0x04034b50 {
			flags := binary.LittleEndian.Uint16(fileData[6:8])
			method := binary.LittleEndian.Uint16(fileData[8:10])
			modTime := binary.LittleEndian.Uint16(fileData[10:12])
			fileCRC := binary.LittleEndian.Uint32(fileData[14:18])
			compSize := int(binary.LittleEndian.Uint32(fileData[18:22]))
			nameLen := int(binary.LittleEndian.Uint16(fileData[26:28]))
			extraLen := int(binary.LittleEndian.Uint16(fileData[28:30]))
			dataOff := 30 + nameLen + extraLen

			if flags&1 != 0 && method != 99 && compSize > 12 && len(fileData) >= dataOff+compSize {
				t := &zipTarget{
					crcCheck:    byte(fileCRC >> 24),
					timeCheck:   byte(modTime >> 8),
					compData:    fileData[dataOff+12 : dataOff+compSize],
					expectedCRC: fileCRC,
				}
				copy(t.encHeader[:], fileData[dataOff:dataOff+12])
				target = t
			}
		}
		mode = "ZIP library"
		if target != nil {
			mode = "ZIP ZipCrypto (fast)"
		}
	case fileKindPDF:
		fmt.Printf("File:    %s (PDF)\n", path)
		pdfT, err = parsePDFTarget(fileData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unsupported/invalid encrypted PDF: %v\n", err)
			os.Exit(1)
		}
		switch {
		case pdfT.r >= 6:
			mode = "PDF Standard R=6 AES-256"
		case pdfT.r == 5:
			mode = "PDF Standard R=5 AES-256"
		case pdfT.r == 4:
			mode = "PDF Standard R=4 (fast)"
		default:
			mode = fmt.Sprintf("PDF Standard R=%d (fast)", pdfT.r)
		}
	default:
		fmt.Fprintln(os.Stderr, "Unsupported file format (expected ZIP or PDF)")
		os.Exit(1)
	}


	numWorkers := *workers
	if numWorkers < 1 {
		numWorkers = 1
	}
	fmt.Printf("Mode:    %s\n", mode)
	fmt.Printf("Workers: %d\n", numWorkers)

	fromT := time.Date(fromY, time.Month(fromM), fromD, 0, 0, 0, 0, time.UTC)
	toT := time.Date(toY, time.Month(toM), toD, 0, 0, 0, 0, time.UTC)
	totalDays := int(toT.Sub(fromT).Hours()/24) + 1
	candidatesPerDay := int64(10000)
	if sex != sexAll {
		candidatesPerDay = 5000
	}
	totalCandidates := int64(totalDays) * candidatesPerDay
	sexLabel := ""
	if sex == sexMale {
		sexLabel = ", male only"
	} else if sex == sexFemale {
		sexLabel = ", female only"
	}
	fmt.Printf("Search:  ~%s candidates (%s to %s%s)\n",
		formatCount(totalCandidates), fromT.Format("2006-01-02"), toT.Format("2006-01-02"), sexLabel)

	var found atomic.Bool
	var counter atomic.Int64
	dateCh := make(chan dateTask, numWorkers*4)
	resultCh := make(chan string, 1)

	start := time.Now()

	if *benchDur > 0 {
		time.AfterFunc(*benchDur, func() {
			c := counter.Load()
			e := time.Since(start).Seconds()
			fmt.Println()
			if e < 1e-9 {
				e = 1e-9
			}
			fmt.Printf("\nBenchmark: %s | Checked: %s | Speed: %s\n",
				benchDur.String(), formatCount(c), formatRate(float64(c)/e))
			os.Exit(0)
		})
	}

	if *benchDur == 0 {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if found.Load() {
					return
				}
				c := counter.Load()
				e := time.Since(start).Seconds()
				if e > 0.5 {
					rate := float64(c) / e
					eta := ""
					if rate > 0 && c < totalCandidates {
						rem := time.Duration(float64(totalCandidates-c)/rate) * time.Second
						eta = " | ETA: " + rem.Truncate(time.Second).String()
					}
					fmt.Printf("\r  Checked: %s | Speed: %s | Elapsed: %.1fs%s        ",
						formatCount(c), formatRate(rate), e, eta)
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch kind {
			case fileKindZIP:
				if target != nil {
					fastWorker(target, dateCh, &found, &counter, resultCh, sex)
				} else {
					libWorker(fileData, dateCh, &found, &counter, resultCh, sex)
				}
			case fileKindPDF:
				pdfWorker(pdfT, dateCh, &found, &counter, resultCh, sex)
			default:
				return
			}
		}()
	}

	go generateDates(dateCh, &found, fromY, fromM, fromD, toY, toM, toD)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	password, ok := <-resultCh
	elapsed := time.Since(start)
	fmt.Println()
	if ok {
		fmt.Printf("\n*** PASSWORD FOUND: %s ***\n", password)
		fmt.Printf("Time: %s | Checked: %s\n", elapsed.Round(time.Millisecond), formatCount(counter.Load()))
	} else {
		fmt.Printf("\nPassword not found. Checked: %s | Time: %s\n",
			formatCount(counter.Load()), elapsed.Round(time.Millisecond))
	}
}
