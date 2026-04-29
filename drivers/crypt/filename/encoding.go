package filename

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Max-Sum/base32768"
	base14 "github.com/fumiama/go-base16384"
)

const (
	EncodingAuto      = "auto"
	EncodingBase64    = "base64"
	EncodingBase32    = "base32"
	EncodingBase32768 = "base32768"
	EncodingBase16384 = "base16384"
)

type nameEncoding interface {
	Name() string
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}

type base64Encoding struct{}

func (base64Encoding) Name() string { return EncodingBase64 }
func (base64Encoding) EncodeToString(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
func (base64Encoding) DecodeString(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

type base32Encoding struct{}

func (base32Encoding) Name() string { return EncodingBase32 }
func (base32Encoding) EncodeToString(b []byte) string {
	return strings.ToLower(strings.TrimRight(base32.HexEncoding.EncodeToString(b), "="))
}
func (base32Encoding) DecodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, fmt.Errorf("bad base32 filename encoding")
	}
	padding := ((len(s) + 7) &^ 7) - len(s)
	return base32.HexEncoding.DecodeString(strings.ToUpper(s) + "========"[:padding])
}

type base32768Encoding struct{}

func (base32768Encoding) Name() string { return EncodingBase32768 }
func (base32768Encoding) EncodeToString(b []byte) string {
	return base32768.SafeEncoding.EncodeToString(b)
}
func (base32768Encoding) DecodeString(s string) ([]byte, error) {
	return base32768.SafeEncoding.DecodeString(s)
}

type base16384Encoding struct{}

func (base16384Encoding) Name() string { return EncodingBase16384 }
func (base16384Encoding) EncodeToString(b []byte) string {
	return base14.EncodeToString(b)
}
func (base16384Encoding) DecodeString(s string) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("bad base16384 filename encoding")
		}
	}()
	raw, err := base14.UTF82UTF16BE([]byte(s))
	if err != nil {
		return nil, err
	}
	if len(raw) < 2 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("bad base16384 filename encoding")
	}
	return base14.Decode(raw), nil
}

func encodingByName(name string) (nameEncoding, error) {
	switch strings.ToLower(name) {
	case "", EncodingAuto, EncodingBase64:
		return base64Encoding{}, nil
	case EncodingBase32:
		return base32Encoding{}, nil
	case EncodingBase32768:
		return base32768Encoding{}, nil
	case EncodingBase16384:
		return base16384Encoding{}, nil
	default:
		return nil, fmt.Errorf("unknown file name encoding mode %q", name)
	}
}

func decryptEncodings(configured string) ([]nameEncoding, error) {
	if strings.EqualFold(configured, EncodingAuto) || configured == "" {
		return allEncodings(), nil
	}
	first, err := encodingByName(configured)
	if err != nil {
		return nil, err
	}
	encs := []nameEncoding{first}
	for _, enc := range allEncodings() {
		if enc.Name() != first.Name() {
			encs = append(encs, enc)
		}
	}
	return encs, nil
}

func allEncodings() []nameEncoding {
	return []nameEncoding{
		base64Encoding{},
		base32Encoding{},
		base32768Encoding{},
		base16384Encoding{},
	}
}
