package hash_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/TechMDW/hashit/pkg/hash"
)

var expectedHashes = Hashes{
	Adler32: "11be037b",
	MD4:     "99ebf48d202177937f084a873437b85e",
	MD5:     "eb733a00c0c9d336e65691a37ab54293",
	SHA1:    "f48dd853820860816c75d54d0f584dc863327a7c",
	SHA2: SHA2{
		SHA224:     "90f2352402b7da021b46b09bd6f636ff24fa6690935a75719758103f",
		SHA256:     "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
		SHA384:     "29901176dc824ac3fd22227677499f02e4e69477ccc501593cc3dc8c6bfef73a08dfdf4a801723c0479b74d6f1abc372",
		SHA512:     "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
		SHA512_224: "9f090221a70db14eb06f6b7d6356dc79aac843ea621dde19dbce4470",
		SHA512_256: "9fe875600168548c1954aed4f03974ce06b3e17f03a70980190da2d7ef937a43",
	},
	SHA3: SHA3{
		SHA256:   "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931",
		SHA512:   "bb9e2a02237e6f8adcaef9fc14b898b7c80cedc114110472cdf925233621b705963c76e7b113bed3c278ff11671a6d1cdcba545e009ff4c0c02539899241993b",
		Shake128: "ae3bdcf04986a8e7ddd99ac948254693fc32ca6ce3ed278c0c54127f072ba21e",
		Shake256: "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e262dd68c2a2f932847f9610eeb51f8ba1a180ca878c788e900d899538d45c9c4a6",
	},
	FNV: FNV{
		FNV32:  "c164e31b",
		FNV32a: "578fbe87",
		FNV64:  "16d3e0f56019af7b",
		FNV64a: "407715e574ca20e7",
	},
	CRC: CRC{
		CRC32IEEE:       "d308aeb2",
		CRC32Koopman:    "3a49a129",
		CRC32Castagnoli: "3379b4ca",
		CRC64IOS:        "8dff641309b87c72",
		CRC64ECMA:       "8d49d818fdb071a5",
	},
}

func TestHasherMulti(t *testing.T) {
	data := []byte("test data")

	hashes, err := HasherMulti(data)
	if err != nil {
		t.Fatalf("HasherMulti failed: %v", err)
	}

	compareHashes(t, hashes, expectedHashes)
}

func TestHasherMultiFile(t *testing.T) {
	// Create a temporary file with test data
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "testfile")
	data := []byte("test data")
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	hashes, err := HasherMultiFile(filePath)
	if err != nil {
		t.Fatalf("HasherMultiFile failed: %v", err)
	}

	compareHashes(t, hashes, expectedHashes)
}

func compareHashes(t *testing.T, actual, expected Hashes) {
	if actual.Adler32 != expected.Adler32 {
		t.Errorf("Expected Adler32 hash %s, got %s", expected.Adler32, actual.Adler32)
	}
	if actual.MD4 != expected.MD4 {
		t.Errorf("Expected MD4 hash %s, got %s", expected.MD4, actual.MD4)
	}
	if actual.MD5 != expected.MD5 {
		t.Errorf("Expected MD5 hash %s, got %s", expected.MD5, actual.MD5)
	}
	if actual.SHA1 != expected.SHA1 {
		t.Errorf("Expected SHA1 hash %s, got %s", expected.SHA1, actual.SHA1)
	}
	if actual.SHA2.SHA224 != expected.SHA2.SHA224 {
		t.Errorf("Expected SHA224 hash %s, got %s", expected.SHA2.SHA224, actual.SHA2.SHA224)
	}
	if actual.SHA2.SHA256 != expected.SHA2.SHA256 {
		t.Errorf("Expected SHA256 hash %s, got %s", expected.SHA2.SHA256, actual.SHA2.SHA256)
	}
	if actual.SHA2.SHA384 != expected.SHA2.SHA384 {
		t.Errorf("Expected SHA384 hash %s, got %s", expected.SHA2.SHA384, actual.SHA2.SHA384)
	}
	if actual.SHA2.SHA512 != expected.SHA2.SHA512 {
		t.Errorf("Expected SHA512 hash %s, got %s", expected.SHA2.SHA512, actual.SHA2.SHA512)
	}
	if actual.SHA2.SHA512_224 != expected.SHA2.SHA512_224 {
		t.Errorf("Expected SHA512_224 hash %s, got %s", expected.SHA2.SHA512_224, actual.SHA2.SHA512_224)
	}
	if actual.SHA2.SHA512_256 != expected.SHA2.SHA512_256 {
		t.Errorf("Expected SHA512_256 hash %s, got %s", expected.SHA2.SHA512_256, actual.SHA2.SHA512_256)
	}
	if actual.SHA3.SHA256 != expected.SHA3.SHA256 {
		t.Errorf("Expected SHA3-256 hash %s, got %s", expected.SHA3.SHA256, actual.SHA3.SHA256)
	}
	if actual.SHA3.SHA512 != expected.SHA3.SHA512 {
		t.Errorf("Expected SHA3-512 hash %s, got %s", expected.SHA3.SHA512, actual.SHA3.SHA512)
	}
	if actual.SHA3.Shake128 != expected.SHA3.Shake128 {
		t.Errorf("Expected Shake128 hash %s, got %s", expected.SHA3.Shake128, actual.SHA3.Shake128)
	}
	if actual.SHA3.Shake256 != expected.SHA3.Shake256 {
		t.Errorf("Expected Shake256 hash %s, got %s", expected.SHA3.Shake256, actual.SHA3.Shake256)
	}
	if actual.FNV.FNV32 != expected.FNV.FNV32 {
		t.Errorf("Expected FNV32 hash %s, got %s", expected.FNV.FNV32, actual.FNV.FNV32)
	}
	if actual.FNV.FNV32a != expected.FNV.FNV32a {
		t.Errorf("Expected FNV32a hash %s, got %s", expected.FNV.FNV32a, actual.FNV.FNV32a)
	}
	if actual.FNV.FNV64 != expected.FNV.FNV64 {
		t.Errorf("Expected FNV64 hash %s, got %s", expected.FNV.FNV64, actual.FNV.FNV64)
	}
	if actual.FNV.FNV64a != expected.FNV.FNV64a {
		t.Errorf("Expected FNV64a hash %s, got %s", expected.FNV.FNV64a, actual.FNV.FNV64a)
	}
	if actual.CRC.CRC32IEEE != expected.CRC.CRC32IEEE {
		t.Errorf("Expected CRC32IEEE hash %s, got %s", expected.CRC.CRC32IEEE, actual.CRC.CRC32IEEE)
	}
	if actual.CRC.CRC32Koopman != expected.CRC.CRC32Koopman {
		t.Errorf("Expected CRC32Koopman hash %s, got %s", expected.CRC.CRC32Koopman, actual.CRC.CRC32Koopman)
	}
	if actual.CRC.CRC32Castagnoli != expected.CRC.CRC32Castagnoli {
		t.Errorf("Expected CRC32Castagnoli hash %s, got %s", expected.CRC.CRC32Castagnoli, actual.CRC.CRC32Castagnoli)
	}
	if actual.CRC.CRC64IOS != expected.CRC.CRC64IOS {
		t.Errorf("Expected CRC64IOS hash %s, got %s", expected.CRC.CRC64IOS, actual.CRC.CRC64IOS)
	}
	if actual.CRC.CRC64ECMA != expected.CRC.CRC64ECMA {
		t.Errorf("Expected CRC64ECMA hash %s, got %s", expected.CRC.CRC64ECMA, actual.CRC.CRC64ECMA)
	}
}

func TestHasherMultiFile_FileNotExist(t *testing.T) {
	_, err := HasherMultiFile("nonexistentfile")
	if err == nil {
		t.Fatal("Expected error for nonexistent file, got nil")
	}
}
