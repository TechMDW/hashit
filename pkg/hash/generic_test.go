package hash_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	. "github.com/TechMDW/hashit/pkg/hash"
)

var expectedHashesMap = map[string]string{
	"adler32":          "11be037b",
	"md4":              "99ebf48d202177937f084a873437b85e",
	"md5":              "eb733a00c0c9d336e65691a37ab54293",
	"sha1":             "f48dd853820860816c75d54d0f584dc863327a7c",
	"sha224":           "90f2352402b7da021b46b09bd6f636ff24fa6690935a75719758103f",
	"sha256":           "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
	"sha384":           "29901176dc824ac3fd22227677499f02e4e69477ccc501593cc3dc8c6bfef73a08dfdf4a801723c0479b74d6f1abc372",
	"sha512":           "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
	"sha512_224":       "9f090221a70db14eb06f6b7d6356dc79aac843ea621dde19dbce4470",
	"sha512_256":       "9fe875600168548c1954aed4f03974ce06b3e17f03a70980190da2d7ef937a43",
	"sha3_256":         "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931",
	"sha3_512":         "bb9e2a02237e6f8adcaef9fc14b898b7c80cedc114110472cdf925233621b705963c76e7b113bed3c278ff11671a6d1cdcba545e009ff4c0c02539899241993b",
	"Shake128":         "ae3bdcf04986a8e7ddd99ac948254693fc32ca6ce3ed278c0c54127f072ba21e",
	"Shake256":         "be15253026b9a85e01ae54b1939284e8e514fbdad2a3bd5c1c0f437e60548e262dd68c2a2f932847f9610eeb51f8ba1a180ca878c788e900d899538d45c9c4a6",
	"fnv32":            "c164e31b",
	"fnv32a":           "578fbe87",
	"fnv64":            "16d3e0f56019af7b",
	"fnv64a":           "407715e574ca20e7",
	"crc32_ieee":       "d308aeb2",
	"crc32_koopman":    "3a49a129",
	"crc32_castagnoli": "3379b4ca",
	"crc64_iso":        "8dff641309b87c72",
	"crc64_ecma":       "8d49d818fdb071a5",
}

func TestHash(t *testing.T) {
	data := []byte("test data")

	for hashType, expected := range expectedHashesMap {
		t.Run(hashType, func(t *testing.T) {
			genericHash, err := ComputeHash(data, hashType, false)
			if err != nil {
				t.Fatalf("ComputeHash failed for %s: %v", hashType, err)
			}

			if genericHash.HexDigest != expected {
				t.Errorf("Expected %s hash %s, got %s", hashType, expected, genericHash.HexDigest)
			}
		})
	}
}

func TestHashFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "testfile")
	data := []byte("test data")

	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	for hashType, expected := range expectedHashesMap {
		t.Run(hashType, func(t *testing.T) {
			genericHash, err := ComputeHash([]byte(filePath), hashType, true)
			if err != nil {
				t.Fatalf("ComputeHash failed for %s: %v", hashType, err)
			}

			if genericHash.HexDigest != expected {
				t.Errorf("Expected %s hash %s, got %s", hashType, expected, genericHash.HexDigest)
			}
		})
	}
}

func TestComputeHashAvailable(t *testing.T) {
	expectedHashes := []string{
		"adler32", "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384",
		"sha512", "sha512_224", "sha512_256", "sha3_256", "sha3_512",
		"shake128", "shake256", "fnv32", "fnv32a", "fnv64", "fnv64a",
		"crc32_ieee", "crc32_koopman", "crc32_castagnoli", "crc64_iso", "crc64_ecma",
	}

	availableHashes := ComputeHashList()

	expectedMap := make(map[string]struct{}, len(expectedHashes))
	for _, hashType := range expectedHashes {
		expectedMap[hashType] = struct{}{}
	}

	availableMap := make(map[string]struct{}, len(availableHashes))
	for _, hashType := range availableHashes {
		availableMap[hashType] = struct{}{}
	}

	if !reflect.DeepEqual(expectedMap, availableMap) {
		t.Errorf("Expected and available hash types do not match.\nExpected: %v\nAvailable: %v", expectedHashes, availableHashes)
	}
}
