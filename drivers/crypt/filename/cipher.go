package filename

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/crypt/pkcs7"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/lib/version"
	"github.com/rfjakob/eme"
	"golang.org/x/crypto/scrypt"
)

const (
	ModeOff       = "off"
	ModeStandard  = "standard"
	ModeObfuscate = "obfuscate"
	ModeStream    = "stream"

	nameBlockSize = aes.BlockSize
)

var defaultSalt = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}

type Config struct {
	Password                string
	Salt                    string
	PasswordObscured        bool
	FileNameEncryption      string
	DirectoryNameEncryption bool
	FileNameEncoding        string
	EncryptedSuffix         string
	StripOrigExt            bool
}

type Cipher struct {
	mode           string
	dirNameEncrypt bool
	suffix         string
	stripOrigExt   bool
	enc            nameEncoding
	decryptEncs    []nameEncoding
	block          gocipher.Block
	nameKey        [32]byte
	nameTweak      [nameBlockSize]byte
}

func New(cfg Config) (*Cipher, error) {
	mode := strings.ToLower(cfg.FileNameEncryption)
	if mode == "" {
		mode = ModeOff
	}
	switch mode {
	case ModeOff, ModeStandard, ModeObfuscate, ModeStream:
	default:
		return nil, fmt.Errorf("unknown file name encryption mode %q", cfg.FileNameEncryption)
	}
	suffix := cfg.EncryptedSuffix
	if suffix == "" {
		suffix = ".bin"
	}
	enc, err := encodingByName(cfg.FileNameEncoding)
	if err != nil {
		return nil, err
	}
	decryptEncs, err := decryptEncodings(cfg.FileNameEncoding)
	if err != nil {
		return nil, err
	}
	password, salt, err := revealSecrets(cfg)
	if err != nil {
		return nil, err
	}
	block, nameKey, tweak, err := nameCipher(password, salt)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		mode:           mode,
		dirNameEncrypt: cfg.DirectoryNameEncryption,
		suffix:         suffix,
		stripOrigExt:   cfg.StripOrigExt,
		enc:            enc,
		decryptEncs:    decryptEncs,
		block:          block,
		nameKey:        nameKey,
		nameTweak:      tweak,
	}, nil
}

func EncryptFileName(name string, cfg Config) (string, error) {
	c, err := New(cfg)
	if err != nil {
		return "", err
	}
	return c.EncryptFileName(name), nil
}

func DecryptFileName(name string, cfg Config) (string, error) {
	c, err := New(cfg)
	if err != nil {
		return "", err
	}
	return c.DecryptFileName(name)
}

func EncryptDirName(name string, cfg Config) (string, error) {
	c, err := New(cfg)
	if err != nil {
		return "", err
	}
	return c.EncryptDirName(name), nil
}

func DecryptDirName(name string, cfg Config) (string, error) {
	c, err := New(cfg)
	if err != nil {
		return "", err
	}
	return c.DecryptDirName(name)
}

func (c *Cipher) EncryptFileName(in string) string {
	if c.mode == ModeOff {
		return in + c.suffix
	}
	return c.encryptPath(in, true)
}

func (c *Cipher) DecryptFileName(in string) (string, error) {
	if c.mode == ModeOff {
		return c.decryptOffFileName(in)
	}
	var lastErr error
	for _, candidate := range recoverCandidates(in, c.stripOrigExt) {
		for _, enc := range c.decryptEncs {
			out, err := c.decryptPath(candidate, true, enc)
			if err == nil {
				return out, nil
			}
			lastErr = err
		}
	}
	return "", lastErr
}

func (c *Cipher) EncryptDirName(in string) string {
	if c.mode == ModeOff || !c.dirNameEncrypt {
		return in
	}
	return c.encryptPath(in, false)
}

func (c *Cipher) DecryptDirName(in string) (string, error) {
	if c.mode == ModeOff || !c.dirNameEncrypt {
		return in, nil
	}
	var lastErr error
	for _, enc := range c.decryptEncs {
		out, err := c.decryptPath(in, false, enc)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (c *Cipher) encryptPath(in string, isFile bool) string {
	segments := strings.Split(in, "/")
	for i := range segments {
		if isFile && !c.dirNameEncrypt && i != len(segments)-1 {
			continue
		}
		segments[i] = c.encryptVersionedSegment(segments[i], isFile && i == len(segments)-1)
	}
	return strings.Join(segments, "/")
}

func (c *Cipher) decryptPath(in string, isFile bool, enc nameEncoding) (string, error) {
	segments := strings.Split(in, "/")
	for i := range segments {
		if isFile && !c.dirNameEncrypt && i != len(segments)-1 {
			continue
		}
		out, err := c.decryptVersionedSegment(segments[i], isFile && i == len(segments)-1, enc)
		if err != nil {
			return "", err
		}
		segments[i] = out
	}
	return strings.Join(segments, "/"), nil
}

func (c *Cipher) encryptVersionedSegment(segment string, isFileSegment bool) string {
	hasVersion, t, base := splitVersion(segment, isFileSegment)
	switch c.mode {
	case ModeStandard:
		base = c.encryptStandardSegment(base, c.enc)
	case ModeStream:
		base = c.encryptStreamSegment(base, c.enc)
	case ModeObfuscate:
		base = c.obfuscateSegment(base)
	}
	if hasVersion {
		return version.Add(base, t)
	}
	return base
}

func (c *Cipher) decryptVersionedSegment(segment string, isFileSegment bool, enc nameEncoding) (string, error) {
	hasVersion, t, base := splitVersion(segment, isFileSegment)
	var (
		out string
		err error
	)
	switch c.mode {
	case ModeStandard:
		out, err = c.decryptStandardSegment(base, enc)
	case ModeStream:
		out, err = c.decryptStreamSegment(base, enc)
	case ModeObfuscate:
		out, err = c.deobfuscateSegment(base)
	}
	if err != nil {
		return "", err
	}
	if hasVersion {
		return version.Add(out, t), nil
	}
	return out, nil
}

func splitVersion(segment string, enabled bool) (bool, time.Time, string) {
	if !enabled || !version.Match(segment) {
		return false, time.Time{}, segment
	}
	t, base := version.Remove(segment)
	if base == segment {
		return false, time.Time{}, segment
	}
	return true, t, base
}

func (c *Cipher) encryptStandardSegment(plaintext string, enc nameEncoding) string {
	if plaintext == "" {
		return ""
	}
	padded := pkcs7.Pad(nameBlockSize, []byte(plaintext))
	return enc.EncodeToString(eme.Transform(c.block, c.nameTweak[:], padded, eme.DirectionEncrypt))
}

func (c *Cipher) decryptStandardSegment(ciphertext string, enc nameEncoding) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := enc.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	if len(raw)%nameBlockSize != 0 {
		return "", fmt.Errorf("not a multiple of blocksize")
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("too short after filename decode")
	}
	if len(raw) > 2048 {
		return "", fmt.Errorf("too long after filename decode")
	}
	padded := eme.Transform(c.block, c.nameTweak[:], raw, eme.DirectionDecrypt)
	plain, err := pkcs7.Unpad(nameBlockSize, padded)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (c *Cipher) encryptStreamSegment(plaintext string, enc nameEncoding) string {
	if plaintext == "" {
		return ""
	}
	plain := []byte(plaintext)
	out := make([]byte, 4+len(plain))
	binary.BigEndian.PutUint32(out, crc32.ChecksumIEEE(plain))
	c.stream(out[4:], plain)
	return enc.EncodeToString(out)
}

func (c *Cipher) decryptStreamSegment(ciphertext string, enc nameEncoding) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	raw, err := enc.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("too short after filename decode")
	}
	plain := make([]byte, len(raw)-4)
	c.stream(plain, raw[4:])
	if crc32.ChecksumIEEE(plain) != binary.BigEndian.Uint32(raw[:4]) {
		return "", fmt.Errorf("filename crc32 mismatch")
	}
	return string(plain), nil
}

func (c *Cipher) stream(dst, src []byte) {
	gocipher.NewCTR(c.block, c.nameTweak[:]).XORKeyStream(dst, src)
}

func (c *Cipher) decryptOffFileName(in string) (string, error) {
	var lastErr error
	for _, candidate := range recoverCandidates(in, c.stripOrigExt) {
		if candidate == c.suffix || !strings.HasSuffix(candidate, c.suffix) {
			lastErr = fmt.Errorf("not an encrypted file - does not match suffix")
			continue
		}
		out := candidate[:len(candidate)-len(c.suffix)]
		if version.Match(out) {
			_, unversioned := version.Remove(out)
			if unversioned == "" {
				lastErr = fmt.Errorf("not an encrypted file - does not match suffix")
				continue
			}
		}
		return out, nil
	}
	return "", lastErr
}

func recoverCandidates(in string, stripOrigExt bool) []string {
	out := []string{in}
	add := func(s string) {
		for _, existing := range out {
			if existing == s {
				return
			}
		}
		out = append(out, s)
	}

	dir, base := splitLast(in)
	if trimmed := strings.TrimRight(base, "."); trimmed != base {
		add(dir + trimmed)
		base = trimmed
	}
	if stripOrigExt {
		for {
			i := strings.LastIndexByte(base, '.')
			if i <= 0 {
				break
			}
			base = base[:i]
			add(dir + base)
		}
	}
	return out
}

func splitLast(path string) (string, string) {
	i := strings.LastIndexByte(path, '/')
	if i == -1 {
		return "", path
	}
	return path[:i+1], path[i+1:]
}

func revealSecrets(cfg Config) (string, string, error) {
	if !cfg.PasswordObscured {
		return cfg.Password, cfg.Salt, nil
	}
	password, err := obscure.Reveal(cfg.Password)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt password: %w", err)
	}
	if cfg.Salt == "" {
		return password, "", nil
	}
	salt, err := obscure.Reveal(cfg.Salt)
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt salt: %w", err)
	}
	return password, salt, nil
}

func nameCipher(password, salt string) (gocipher.Block, [32]byte, [nameBlockSize]byte, error) {
	const keySize = 32 + 32 + nameBlockSize
	saltBytes := defaultSalt
	if salt != "" {
		saltBytes = []byte(salt)
	}
	var key []byte
	var err error
	if password == "" {
		key = make([]byte, keySize)
	} else {
		key, err = scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, keySize)
		if err != nil {
			return nil, [32]byte{}, [nameBlockSize]byte{}, err
		}
	}
	var nameKey [32]byte
	copy(nameKey[:], key[32:64])
	var tweak [nameBlockSize]byte
	copy(tweak[:], key[64:])
	block, err := aes.NewCipher(nameKey[:])
	if err != nil {
		return nil, [32]byte{}, [nameBlockSize]byte{}, err
	}
	return block, nameKey, tweak, nil
}
