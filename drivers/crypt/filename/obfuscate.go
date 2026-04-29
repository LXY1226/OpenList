package filename

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const obfuscQuoteRune = '!'

func (c *Cipher) obfuscateSegment(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	if !utf8.ValidString(plaintext) {
		return "!." + plaintext
	}
	dir := 0
	for _, r := range plaintext {
		dir += int(r)
	}
	dir %= 256
	var result bytes.Buffer
	result.WriteString(strconv.Itoa(dir) + ".")
	for _, b := range c.nameKey {
		dir += int(b)
	}
	for _, r := range plaintext {
		switch {
		case r == obfuscQuoteRune:
			result.WriteRune(obfuscQuoteRune)
			result.WriteRune(obfuscQuoteRune)
		case r >= '0' && r <= '9':
			thisDir := (dir % 9) + 1
			result.WriteRune(rune('0' + (int(r)-'0'+thisDir)%10))
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			thisDir := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6
			}
			pos = (pos + thisDir) % 52
			if pos >= 26 {
				pos += 6
			}
			result.WriteRune(rune('A' + pos))
		case r >= 0xA0 && r <= 0xFF:
			thisDir := (dir % 95) + 1
			result.WriteRune(rune(0xA0 + (int(r)-0xA0+thisDir)%96))
		case r >= 0x100:
			thisDir := (dir % 127) + 1
			base := int(r - r%256)
			nr := rune(base + (int(r)-base+thisDir)%256)
			if !utf8.ValidRune(nr) {
				result.WriteRune(obfuscQuoteRune)
				result.WriteRune(r)
			} else {
				result.WriteRune(nr)
			}
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

func (c *Cipher) deobfuscateSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	pos := strings.Index(ciphertext, ".")
	if pos == -1 {
		return "", fmt.Errorf("not an encrypted file")
	}
	num := ciphertext[:pos]
	if num == "!" {
		return ciphertext[pos+1:], nil
	}
	dir, err := strconv.Atoi(num)
	if err != nil {
		return "", fmt.Errorf("not an encrypted file")
	}
	for _, b := range c.nameKey {
		dir += int(b)
	}
	var result bytes.Buffer
	inQuote := false
	for _, r := range ciphertext[pos+1:] {
		switch {
		case inQuote:
			result.WriteRune(r)
			inQuote = false
		case r == obfuscQuoteRune:
			inQuote = true
		case r >= '0' && r <= '9':
			thisDir := (dir % 9) + 1
			nr := '0' + int(r) - '0' - thisDir
			if nr < '0' {
				nr += 10
			}
			result.WriteRune(rune(nr))
		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			thisDir := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6
			}
			pos -= thisDir
			if pos < 0 {
				pos += 52
			}
			if pos >= 26 {
				pos += 6
			}
			result.WriteRune(rune('A' + pos))
		case r >= 0xA0 && r <= 0xFF:
			thisDir := (dir % 95) + 1
			nr := 0xA0 + int(r) - 0xA0 - thisDir
			if nr < 0xA0 {
				nr += 96
			}
			result.WriteRune(rune(nr))
		case r >= 0x100:
			thisDir := (dir % 127) + 1
			base := int(r - r%256)
			nr := rune(base + (int(r) - base - thisDir))
			if int(nr) < base {
				nr += 256
			}
			result.WriteRune(nr)
		default:
			result.WriteRune(r)
		}
	}
	return result.String(), nil
}
