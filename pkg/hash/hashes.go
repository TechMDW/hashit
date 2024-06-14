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
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

type Hashes struct {
	Adler32     string `json:"adler32"`
	MD4         string `json:"md4"`
	MD5         string `json:"md5"`
	SHA1        string `json:"sha1"`
	SHA2        SHA2   `json:"sha2"`
	SHA3        SHA3   `json:"sha3"`
	FNV         FNV    `json:"fnv"`
	CRC         CRC    `json:"crc"`
	Blake       Blake  `json:"blake"`
	Duration    int64  `json:"duration"`
	DurationStr string `json:"durationStr"`
}

type SHA2 struct {
	SHA224     string `json:"sha224"`
	SHA256     string `json:"sha256"`
	SHA384     string `json:"sha384"`
	SHA512     string `json:"sha512"`
	SHA512_224 string `json:"sha512_224"`
	SHA512_256 string `json:"sha512_256"`
}

type SHA3 struct {
	SHA256   string `json:"sha3_256"`
	SHA512   string `json:"sha3_512"`
	Shake128 string `json:"shake128"`
	Shake256 string `json:"shake256"`
}

type FNV struct {
	FNV32  string `json:"fnv32"`
	FNV32a string `json:"fnv32a"`
	FNV64  string `json:"fnv64"`
	FNV64a string `json:"fnv64a"`
}

type CRC struct {
	CRC32IEEE       string `json:"crc32_IEEE"`
	CRC32Koopman    string `json:"crc32_Koopman"`
	CRC32Castagnoli string `json:"crc32_Castagnoli"`
	CRC64IOS        string `json:"crc64_ISO"`
	CRC64ECMA       string `json:"crc64_ECMA"`
}

type Blake struct {
	Blake2b256 string `json:"blake2b256"`
	Blake2b384 string `json:"blake2b384"`
	Blake2b512 string `json:"blake2b512"`
	Blake2s256 string `json:"blake2s256"`
}

type HasherArray struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
}

func (h Hashes) Array() []HasherArray {
	return []HasherArray{
		{Type: "adler32", Hash: h.Adler32},
		{Type: "md4", Hash: h.MD4},
		{Type: "md5", Hash: h.MD5},
		{Type: "sha1", Hash: h.SHA1},
		{Type: "sha224", Hash: h.SHA2.SHA224},
		{Type: "sha256", Hash: h.SHA2.SHA256},
		{Type: "sha384", Hash: h.SHA2.SHA384},
		{Type: "sha512", Hash: h.SHA2.SHA512},
		{Type: "sha512_224", Hash: h.SHA2.SHA512_224},
		{Type: "sha512_256", Hash: h.SHA2.SHA512_256},
		{Type: "sha3_256", Hash: h.SHA3.SHA256},
		{Type: "sha3_512", Hash: h.SHA3.SHA512},
		{Type: "shake128", Hash: h.SHA3.Shake128},
		{Type: "shake256", Hash: h.SHA3.Shake256},
		{Type: "fnv32", Hash: h.FNV.FNV32},
		{Type: "fnv32a", Hash: h.FNV.FNV32a},
		{Type: "fnv64", Hash: h.FNV.FNV64},
		{Type: "fnv64a", Hash: h.FNV.FNV64a},
		{Type: "crc32_IEEE", Hash: h.CRC.CRC32IEEE},
		{Type: "crc32_Koopman", Hash: h.CRC.CRC32Koopman},
		{Type: "crc32_Castagnoli", Hash: h.CRC.CRC32Castagnoli},
		{Type: "crc64_ISO", Hash: h.CRC.CRC64IOS},
		{Type: "crc64_ECMA", Hash: h.CRC.CRC64ECMA},
		{Type: "blake2b256", Hash: h.Blake.Blake2b256},
		{Type: "blake2b384", Hash: h.Blake.Blake2b384},
		{Type: "blake2b512", Hash: h.Blake.Blake2b512},
		{Type: "blake2s256", Hash: h.Blake.Blake2s256},
	}
}

func initializeHashers() ([]hash.Hash, *Hashes) {
	hashes := &Hashes{}

	hashers := []hash.Hash{
		adler32.New(),
		md4.New(),
		md5.New(),
		sha1.New(),
		sha256.New224(),
		sha256.New(),
		sha512.New384(),
		sha512.New(),
		sha512.New512_224(),
		sha512.New512_256(),
		sha3.New256(),
		sha3.New512(),
		sha3.NewShake128(),
		sha3.NewShake256(),
		fnv.New32(),
		fnv.New32a(),
		fnv.New64(),
		fnv.New64a(),
		crc32.NewIEEE(),
		crc32.New(crc32.MakeTable(crc32.Koopman)),
		crc32.New(crc32.MakeTable(crc32.Castagnoli)),
		crc64.New(crc64.MakeTable(crc64.ISO)),
		crc64.New(crc64.MakeTable(crc64.ECMA)),
	}

	blake2b256, _ := blake2b.New256(nil)
	blake2b384, _ := blake2b.New384(nil)
	blake2b512, _ := blake2b.New512(nil)
	blake2s256, _ := blake2s.New256(nil)

	hashers = append(hashers, blake2b256, blake2b384, blake2b512, blake2s256)

	return hashers, hashes
}

func setHashes(hashes *Hashes, hashers []hash.Hash) {
	hashes.Adler32 = fmt.Sprintf("%x", hashers[0].Sum(nil))
	hashes.MD4 = fmt.Sprintf("%x", hashers[1].Sum(nil))
	hashes.MD5 = fmt.Sprintf("%x", hashers[2].Sum(nil))
	hashes.SHA1 = fmt.Sprintf("%x", hashers[3].Sum(nil))
	hashes.SHA2.SHA224 = fmt.Sprintf("%x", hashers[4].Sum(nil))
	hashes.SHA2.SHA256 = fmt.Sprintf("%x", hashers[5].Sum(nil))
	hashes.SHA2.SHA384 = fmt.Sprintf("%x", hashers[6].Sum(nil))
	hashes.SHA2.SHA512 = fmt.Sprintf("%x", hashers[7].Sum(nil))
	hashes.SHA2.SHA512_224 = fmt.Sprintf("%x", hashers[8].Sum(nil))
	hashes.SHA2.SHA512_256 = fmt.Sprintf("%x", hashers[9].Sum(nil))
	hashes.SHA3.SHA256 = fmt.Sprintf("%x", hashers[10].Sum(nil))
	hashes.SHA3.SHA512 = fmt.Sprintf("%x", hashers[11].Sum(nil))
	hashes.SHA3.Shake128 = fmt.Sprintf("%x", hashers[12].Sum(nil))
	hashes.SHA3.Shake256 = fmt.Sprintf("%x", hashers[13].Sum(nil))
	hashes.FNV.FNV32 = fmt.Sprintf("%x", hashers[14].Sum(nil))
	hashes.FNV.FNV32a = fmt.Sprintf("%x", hashers[15].Sum(nil))
	hashes.FNV.FNV64 = fmt.Sprintf("%x", hashers[16].Sum(nil))
	hashes.FNV.FNV64a = fmt.Sprintf("%x", hashers[17].Sum(nil))
	hashes.CRC.CRC32IEEE = fmt.Sprintf("%x", hashers[18].Sum(nil))
	hashes.CRC.CRC32Koopman = fmt.Sprintf("%x", hashers[19].Sum(nil))
	hashes.CRC.CRC32Castagnoli = fmt.Sprintf("%x", hashers[20].Sum(nil))
	hashes.CRC.CRC64IOS = fmt.Sprintf("%x", hashers[21].Sum(nil))
	hashes.CRC.CRC64ECMA = fmt.Sprintf("%x", hashers[22].Sum(nil))
	hashes.Blake.Blake2b256 = fmt.Sprintf("%x", hashers[23].Sum(nil))
	hashes.Blake.Blake2b384 = fmt.Sprintf("%x", hashers[24].Sum(nil))
	hashes.Blake.Blake2b512 = fmt.Sprintf("%x", hashers[25].Sum(nil))
	hashes.Blake.Blake2s256 = fmt.Sprintf("%x", hashers[26].Sum(nil))
}

func HasherMulti(b []byte) (Hashes, error) {
	timeStart := time.Now()
	hashers, hashes := initializeHashers()

	var wg sync.WaitGroup
	chunkSize := BufferSize

	for i := 0; i < len(b); i += chunkSize {
		end := i + chunkSize
		if end > len(b) {
			end = len(b)
		}

		chunk := b[i:end]
		for _, hasher := range hashers {
			wg.Add(1)
			go func(h hash.Hash, d []byte) {
				defer wg.Done()
				h.Write(d)
			}(hasher, chunk)
		}
	}

	wg.Wait()

	setHashes(hashes, hashers)
	timeSince := time.Since(timeStart)
	hashes.Duration = timeSince.Milliseconds()
	hashes.DurationStr = timeSince.String()
	return *hashes, nil
}

func HasherMultiFile(path string) (Hashes, error) {
	timeStart := time.Now()
	hashers, hashes := initializeHashers()

	file, err := os.Open(path)
	if err != nil {
		return Hashes{}, err
	}
	defer file.Close()

	var wg sync.WaitGroup
	buf := make([]byte, BufferSize)

	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return Hashes{}, err
		}
		if n == 0 {
			break
		}

		chunk := make([]byte, n)
		copy(chunk, buf[:n])

		for _, hasher := range hashers {
			wg.Add(1)
			go func(h hash.Hash, d []byte) {
				defer wg.Done()
				h.Write(d)
			}(hasher, chunk)
		}

		wg.Wait()
	}

	setHashes(hashes, hashers)
	timeSince := time.Since(timeStart)
	hashes.Duration = timeSince.Milliseconds()
	hashes.DurationStr = timeSince.String()
	return *hashes, nil
}
