package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

const (
	BufferSize = 1024 * 1024 * 4
)

// GenericHash represents a hash of data.
type GenericHash struct {
	Input       []byte `json:"input"`
	HashBytes   []byte `json:"hashBytes"`
	HexDigest   string `json:"hexDigest"`
	Duration    int64  `json:"duration"`
	DurationStr string `json:"durationStr"`
}

// Hash returns a hash of the data using the specified hash type.
func Hash(data []byte, hash hash.Hash) *GenericHash {
	timeStart := time.Now()

	gh := &GenericHash{
		Input: data,
	}

	hash.Write(data)
	gh.HashBytes = hash.Sum(nil)
	gh.HexDigest = fmt.Sprintf("%x", gh.HashBytes)
	timeSince := time.Since(timeStart)
	gh.Duration = timeSince.Milliseconds()
	gh.DurationStr = timeSince.String()

	return gh
}

// HashFile returns a hash of the file using the specified hash type.
func HashFile(path string, hash hash.Hash) (*GenericHash, error) {
	timeStart := time.Now()

	gh := &GenericHash{
		Input: []byte(path),
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, BufferSize)
	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		hash.Write(buf[:n])
	}

	gh.HashBytes = hash.Sum(nil)
	gh.HexDigest = fmt.Sprintf("%x", gh.HashBytes)
	timeSince := time.Since(timeStart)
	gh.Duration = timeSince.Milliseconds()
	gh.DurationStr = timeSince.String()

	return gh, nil
}

// ComputeHash returns a hash of the data using the specified hash type.
func ComputeHash(data []byte, hashType string, file bool) (*GenericHash, error) {
	var hasher hash.Hash

	hashType = strings.ToLower(hashType)
	switch hashType {
	case "adler32":
		hasher = adler32.New()
	case "md4":
		hasher = md4.New()
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha224":
		hasher = sha256.New224()
	case "sha256":
		hasher = sha256.New()
	case "sha384":
		hasher = sha512.New384()
	case "sha512":
		hasher = sha512.New()
	case "sha512_224":
		hasher = sha512.New512_224()
	case "sha512_256":
		hasher = sha512.New512_256()
	case "sha3_256":
		hasher = sha3.New256()
	case "sha3_512":
		hasher = sha3.New512()
	case "shake128":
		hasher = sha3.NewShake128()
	case "shake256":
		hasher = sha3.NewShake256()
	case "fnv32":
		hasher = fnv.New32()
	case "fnv32a":
		hasher = fnv.New32a()
	case "fnv64":
		hasher = fnv.New64()
	case "fnv64a":
		hasher = fnv.New64a()
	case "crc32_ieee":
		hasher = crc32.NewIEEE()
	case "crc32_koopman":
		hasher = crc32.New(crc32.MakeTable(crc32.Koopman))
	case "crc32_castagnoli":
		hasher = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "crc64_iso":
		hasher = crc64.New(crc64.MakeTable(crc64.ISO))
	case "crc64_ecma":
		hasher = crc64.New(crc64.MakeTable(crc64.ECMA))
	case "blake2b256":
		hasher, _ = blake2b.New256(nil)
	case "blake2b384":
		hasher, _ = blake2b.New384(nil)
	case "blake2b512":
		hasher, _ = blake2b.New512(nil)
	case "blake2s256":
		hasher, _ = blake2s.New256(nil)
	default:
		return &GenericHash{}, fmt.Errorf("unknown hash type: %s", hashType)
	}

	if file {
		return HashFile(string(data), hasher)
	}

	return Hash(data, hasher), nil
}

// ComputeHashList returns a list of all available hash types.
func ComputeHashList() []string {
	return []string{
		"adler32",
		"md4",
		"md5",
		"sha1",
		"sha224",
		"sha256",
		"sha384",
		"sha512",
		"sha512_224",
		"sha512_256",
		"sha3_256",
		"sha3_512",
		"shake128",
		"shake256",
		"fnv32",
		"fnv32a",
		"fnv64",
		"fnv64a",
		"crc32_ieee",
		"crc32_koopman",
		"crc32_castagnoli",
		"crc64_iso",
		"crc64_ecma",
		"blake2b256",
		"blake2b384",
		"blake2b512",
		"blake2s256",
	}
}
