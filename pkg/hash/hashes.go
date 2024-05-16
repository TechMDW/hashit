package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"os"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

type Hashes struct {
	Adler32 string `json:"adler32"`
	MD4     string `json:"md4"`
	MD5     string `json:"md5"`
	SHA1    string `json:"sha1"`
	SHA2    SHA2   `json:"sha2"`
	SHA3    SHA3   `json:"sha3"`
	FNV     FNV    `json:"fnv"`
	CRC     CRC    `json:"crc"`
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

type HasherArray struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
}

func (h Hashes) Array() []HasherArray {
	hashes := []HasherArray{
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
		{Type: "sha3_shake128", Hash: h.SHA3.Shake128},
		{Type: "sha3_shake256", Hash: h.SHA3.Shake256},
		{Type: "fnv32", Hash: h.FNV.FNV32},
		{Type: "fnv32a", Hash: h.FNV.FNV32a},
		{Type: "fnv64", Hash: h.FNV.FNV64},
		{Type: "fnv64a", Hash: h.FNV.FNV64a},
		{Type: "crc32_IEEE", Hash: h.CRC.CRC32IEEE},
		{Type: "crc32_Koopman", Hash: h.CRC.CRC32Koopman},
		{Type: "crc32_Castagnoli", Hash: h.CRC.CRC32Castagnoli},
		{Type: "crc64_ISO", Hash: h.CRC.CRC64IOS},
		{Type: "crc64_ECMA", Hash: h.CRC.CRC64ECMA},
	}

	return hashes
}

func HasherMulti(b []byte) (Hashes, error) {
	// Adler
	hasherAdler := adler32.New()

	// MD4
	hasherMD4 := md4.New()

	// MD5
	hasherMD5 := md5.New()

	// SHA1
	hasherSHA1 := sha1.New()

	// SHA2
	hasherSHA244 := sha256.New224()
	hasherSHA256 := sha256.New()
	hasherSHA384 := sha512.New384()
	hasherSHA512 := sha512.New()
	hasherSHA512_224 := sha512.New512_224()
	hasherSHA512_256 := sha512.New512_256()

	// SHA3
	hasherSHA3_256 := sha3.New256()
	hasherSHA3_512 := sha3.New512()
	hasherSHA3_Shake128 := sha3.NewShake128()
	hasherSHA3_Shake256 := sha3.NewShake256()

	// FNV
	hasherFnv32 := fnv.New32()
	hasherFnv32a := fnv.New32a()
	hasherFnv64 := fnv.New64()
	hasherFnv64a := fnv.New64a()

	// CRC
	hasherCRC32IEEE := crc32.NewIEEE()
	hasherCRC32Koopman := crc32.New(crc32.MakeTable(crc32.Koopman))
	hasherCRC32Castagnoli := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	hasherCRC64ISO := crc64.New(crc64.MakeTable(crc64.ISO))
	hasherCRC64ECMA := crc64.New(crc64.MakeTable(crc64.ECMA))

	hashers := []io.Writer{
		hasherAdler,
		hasherMD4,
		hasherMD5,
		hasherSHA1,
		hasherSHA244,
		hasherSHA256,
		hasherSHA384,
		hasherSHA512,
		hasherSHA512_224,
		hasherSHA512_256,
		hasherSHA3_256,
		hasherSHA3_512,
		hasherSHA3_Shake128,
		hasherSHA3_Shake256,
		hasherFnv32,
		hasherFnv32a,
		hasherFnv64,
		hasherFnv64a,
		hasherCRC32IEEE,
		hasherCRC32Koopman,
		hasherCRC32Castagnoli,
		hasherCRC64ISO,
		hasherCRC64ECMA,
	}

	multiWriter := io.MultiWriter(
		hashers...,
	)

	_, err := multiWriter.Write(b)
	if err != nil {
		return Hashes{}, err
	}

	hash := Hashes{
		Adler32: fmt.Sprintf("%x", hasherAdler.Sum(nil)),
		MD4:     fmt.Sprintf("%x", hasherMD4.Sum(nil)),
		MD5:     fmt.Sprintf("%x", hasherMD5.Sum(nil)),
		SHA1:    fmt.Sprintf("%x", hasherSHA1.Sum(nil)),
		SHA2: SHA2{
			SHA224:     fmt.Sprintf("%x", hasherSHA244.Sum(nil)),
			SHA256:     fmt.Sprintf("%x", hasherSHA256.Sum(nil)),
			SHA384:     fmt.Sprintf("%x", hasherSHA384.Sum(nil)),
			SHA512:     fmt.Sprintf("%x", hasherSHA512.Sum(nil)),
			SHA512_224: fmt.Sprintf("%x", hasherSHA512_224.Sum(nil)),
			SHA512_256: fmt.Sprintf("%x", hasherSHA512_256.Sum(nil)),
		},
		SHA3: SHA3{
			SHA256:   fmt.Sprintf("%x", hasherSHA3_256.Sum(nil)),
			SHA512:   fmt.Sprintf("%x", hasherSHA3_512.Sum(nil)),
			Shake128: fmt.Sprintf("%x", hasherSHA3_Shake128.Sum(nil)),
			Shake256: fmt.Sprintf("%x", hasherSHA3_Shake256.Sum(nil)),
		},
		FNV: FNV{
			FNV32:  fmt.Sprintf("%x", hasherFnv32.Sum(nil)),
			FNV32a: fmt.Sprintf("%x", hasherFnv32a.Sum(nil)),
			FNV64:  fmt.Sprintf("%x", hasherFnv64.Sum(nil)),
			FNV64a: fmt.Sprintf("%x", hasherFnv64a.Sum(nil)),
		},
		CRC: CRC{
			CRC32IEEE:       fmt.Sprintf("%x", hasherCRC32IEEE.Sum(nil)),
			CRC32Koopman:    fmt.Sprintf("%x", hasherCRC32Koopman.Sum(nil)),
			CRC32Castagnoli: fmt.Sprintf("%x", hasherCRC32Castagnoli.Sum(nil)),
			CRC64IOS:        fmt.Sprintf("%x", hasherCRC64ISO.Sum(nil)),
			CRC64ECMA:       fmt.Sprintf("%x", hasherCRC64ECMA.Sum(nil)),
		},
	}

	return hash, nil
}

func HasherMultiFile(path string) (Hashes, error) {
	// Adler
	hasherAdler := adler32.New()

	// MD4
	hasherMD4 := md4.New()

	// MD5
	hasherMD5 := md5.New()

	// SHA1
	hasherSHA1 := sha1.New()

	// SHA2
	hasherSHA244 := sha256.New224()
	hasherSHA256 := sha256.New()
	hasherSHA384 := sha512.New384()
	hasherSHA512 := sha512.New()
	hasherSHA512_224 := sha512.New512_224()
	hasherSHA512_256 := sha512.New512_256()

	// SHA3
	hasherSHA3_256 := sha3.New256()
	hasherSHA3_512 := sha3.New512()
	hasherSHA3_Shake128 := sha3.NewShake128()
	hasherSHA3_Shake256 := sha3.NewShake256()

	// FNV
	hasherFnv32 := fnv.New32()
	hasherFnv32a := fnv.New32a()
	hasherFnv64 := fnv.New64()
	hasherFnv64a := fnv.New64a()

	// CRC
	hasherCRC32IEEE := crc32.NewIEEE()
	hasherCRC32Koopman := crc32.New(crc32.MakeTable(crc32.Koopman))
	hasherCRC32Castagnoli := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	hasherCRC64ISO := crc64.New(crc64.MakeTable(crc64.ISO))
	hasherCRC64ECMA := crc64.New(crc64.MakeTable(crc64.ECMA))

	hashers := []io.Writer{
		hasherAdler,
		hasherMD4,
		hasherMD5,
		hasherSHA1,
		hasherSHA244,
		hasherSHA256,
		hasherSHA384,
		hasherSHA512,
		hasherSHA512_224,
		hasherSHA512_256,
		hasherSHA3_256,
		hasherSHA3_512,
		hasherSHA3_Shake128,
		hasherSHA3_Shake256,
		hasherFnv32,
		hasherFnv32a,
		hasherFnv64,
		hasherFnv64a,
		hasherCRC32IEEE,
		hasherCRC32Koopman,
		hasherCRC32Castagnoli,
		hasherCRC64ISO,
		hasherCRC64ECMA,
	}

	multiWriter := io.MultiWriter(
		hashers...,
	)

	file, err := os.Open(path)
	if err != nil {
		return Hashes{}, err
	}
	defer file.Close()

	_, err = io.Copy(multiWriter, file)
	if err != nil {
		return Hashes{}, err
	}

	hash := Hashes{
		Adler32: fmt.Sprintf("%x", hasherAdler.Sum(nil)),
		MD4:     fmt.Sprintf("%x", hasherMD4.Sum(nil)),
		MD5:     fmt.Sprintf("%x", hasherMD5.Sum(nil)),
		SHA1:    fmt.Sprintf("%x", hasherSHA1.Sum(nil)),
		SHA2: SHA2{
			SHA224:     fmt.Sprintf("%x", hasherSHA244.Sum(nil)),
			SHA256:     fmt.Sprintf("%x", hasherSHA256.Sum(nil)),
			SHA384:     fmt.Sprintf("%x", hasherSHA384.Sum(nil)),
			SHA512:     fmt.Sprintf("%x", hasherSHA512.Sum(nil)),
			SHA512_224: fmt.Sprintf("%x", hasherSHA512_224.Sum(nil)),
			SHA512_256: fmt.Sprintf("%x", hasherSHA512_256.Sum(nil)),
		},
		SHA3: SHA3{
			SHA256:   fmt.Sprintf("%x", hasherSHA3_256.Sum(nil)),
			SHA512:   fmt.Sprintf("%x", hasherSHA3_512.Sum(nil)),
			Shake128: fmt.Sprintf("%x", hasherSHA3_Shake128.Sum(nil)),
			Shake256: fmt.Sprintf("%x", hasherSHA3_Shake256.Sum(nil)),
		},
		FNV: FNV{
			FNV32:  fmt.Sprintf("%x", hasherFnv32.Sum(nil)),
			FNV32a: fmt.Sprintf("%x", hasherFnv32a.Sum(nil)),
			FNV64:  fmt.Sprintf("%x", hasherFnv64.Sum(nil)),
			FNV64a: fmt.Sprintf("%x", hasherFnv64a.Sum(nil)),
		},
		CRC: CRC{
			CRC32IEEE:       fmt.Sprintf("%x", hasherCRC32IEEE.Sum(nil)),
			CRC32Koopman:    fmt.Sprintf("%x", hasherCRC32Koopman.Sum(nil)),
			CRC32Castagnoli: fmt.Sprintf("%x", hasherCRC32Castagnoli.Sum(nil)),
			CRC64IOS:        fmt.Sprintf("%x", hasherCRC64ISO.Sum(nil)),
			CRC64ECMA:       fmt.Sprintf("%x", hasherCRC64ECMA.Sum(nil)),
		},
	}

	return hash, nil

}
