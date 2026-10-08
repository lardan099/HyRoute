package backup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// An encrypted backup is the database sealed with a key derived from a
// passphrase (argon2id) in chunks of AES-256-GCM:
//
//	magic "HRBACKUP", format 1, argon2id time (u32), memory KiB (u32),
//	threads (u8), salt (16), nonce prefix (7), then the chunks.
//
// A chunk is up to 64 KiB of the database plus a 16-byte tag; its nonce is
// the prefix, the chunk number (u32) and a byte that marks the last chunk,
// and the header is the additional data of every chunk: chunks cannot be
// reordered, dropped or cut off at the end without the last one failing.
var cryptMagic = [8]byte{'H', 'R', 'B', 'A', 'C', 'K', 'U', 'P'}

const (
	cryptFormat  = 1
	saltSize     = 16
	prefixSize   = 7
	headerSize   = len(cryptMagic) + 1 + 4 + 4 + 1 + saltSize + prefixSize
	chunkSize    = 64 << 10
	tagSize      = 16
	maxKDFMemory = 1 << 20 // KiB: 1 GiB
	maxKDFTime   = 16
)

// kdfParams are the argon2id parameters of a new encrypted backup; tests
// lower them.
var kdfParams = struct {
	time, memory uint32
	threads      uint8
}{3, 64 << 10, 2}

// ErrPassphrase: the passphrase does not open the backup, or the file was
// damaged.
var ErrPassphrase = errors.New("парольная фраза не подходит к копии, или файл копии повреждён")

// Encrypted reports whether the start of a file is an encrypted backup.
func Encrypted(head []byte) bool {
	return len(head) >= len(cryptMagic) && bytes.Equal(head[:len(cryptMagic)], cryptMagic[:])
}

func chunkAEAD(passphrase string, salt []byte, passes, memory uint32, threads uint8) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(passphrase), salt, passes, memory, threads, 32)
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func chunkNonce(prefix []byte, n uint32, last bool) []byte {
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, prefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, n)
	if last {
		return append(nonce, 1)
	}
	return append(nonce, 0)
}

// encrypt writes r to w sealed with passphrase.
func encrypt(w io.Writer, r io.Reader, passphrase string) error {
	if passphrase == "" {
		return errors.New("empty passphrase")
	}
	header := make([]byte, 0, headerSize)
	header = append(header, cryptMagic[:]...)
	header = append(header, cryptFormat)
	header = binary.BigEndian.AppendUint32(header, kdfParams.time)
	header = binary.BigEndian.AppendUint32(header, kdfParams.memory)
	header = append(header, kdfParams.threads)
	random := make([]byte, saltSize+prefixSize)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	header = append(header, random...)
	salt, prefix := random[:saltSize], random[saltSize:]
	aead, err := chunkAEAD(passphrase, salt, kdfParams.time, kdfParams.memory, kdfParams.threads)
	if err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	// A full chunk is sealed once the next byte shows it is not the last.
	br := bufio.NewReaderSize(r, chunkSize+1)
	buf := make([]byte, chunkSize)
	out := make([]byte, 0, chunkSize+tagSize)
	for n := uint32(0); ; n++ {
		k, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		last := k < chunkSize
		if !last {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		out = aead.Seal(out[:0], chunkNonce(prefix, n, last), buf[:k], header)
		if _, err := w.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
		if n == ^uint32(0) {
			return errors.New("backup too large")
		}
	}
}

// decrypt writes the database of an encrypted backup r to w.
func decrypt(w io.Writer, r io.Reader, passphrase string) error {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("%w: %v", ErrPassphrase, err)
	}
	if !Encrypted(header) {
		return errors.New("not an encrypted backup")
	}
	p := header[len(cryptMagic):]
	if p[0] != cryptFormat {
		return fmt.Errorf("encrypted backup format %d: this hyroute-server reads format %d, update it", p[0], cryptFormat)
	}
	passes, memory, threads := binary.BigEndian.Uint32(p[1:5]), binary.BigEndian.Uint32(p[5:9]), p[9]
	if passes == 0 || passes > maxKDFTime || memory == 0 || memory > maxKDFMemory || threads == 0 {
		return fmt.Errorf("%w: key derivation parameters out of range", ErrPassphrase)
	}
	salt, prefix := p[10:10+saltSize], p[10+saltSize:]
	aead, err := chunkAEAD(passphrase, salt, passes, memory, threads)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, chunkSize+tagSize+1)
	buf := make([]byte, chunkSize+tagSize)
	out := make([]byte, 0, chunkSize)
	for n := uint32(0); ; n++ {
		k, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		last := k < len(buf)
		if !last {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		out, err = aead.Open(out[:0], chunkNonce(prefix, n, last), buf[:k], header)
		if err != nil {
			return ErrPassphrase
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}
