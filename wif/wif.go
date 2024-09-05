package wif

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

// Base58 alphabet
var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Ponto gerador pré-calculado
var curve = secp256k1.S256()

// GeneratePublicKey generates a compressed public key from a private key.
func GeneratePublicKey(privKeyBytes []byte) []byte {
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	pubKey := privKey.PubKey()
	return pubKey.SerializeCompressed()
}

// PublicKeyToAddress converts a public key to a Bitcoin address.
func PublicKeyToAddress(pubKey []byte) string {
	pubKeyHash := Hash160(pubKey)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	return base58EncodeWithChecksum(versionedPayload)
}

// PrivateKeyToWIF converts a private key to Wallet Import Format.
func PrivateKeyToWIF(privKey *big.Int) string {
	privKeyBytes := privKey.FillBytes(make([]byte, 32)) // Fill to 32 bytes
	payload := append([]byte{0x80}, privKeyBytes...)
	payload = append(payload, 0x01) // Compressed key indicator
	return base58EncodeWithChecksum(payload)
}

// AddressToHash160 converts a Bitcoin address to its corresponding hash160.
func AddressToHash160(address string) []byte {
	payload := base58Decode(address)
	return payload[1 : len(payload)-4]
}

// Hash160 computes RIPEMD-160 after SHA-256.
func Hash160(data []byte) []byte {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:])
	return ripemd160Hasher.Sum(nil)
}

// base58EncodeWithChecksum encodes data in Base58 with a checksum.
func base58EncodeWithChecksum(payload []byte) string {
	checksum := checksum(payload)
	fullPayload := append(payload, checksum...)
	return base58Encode(fullPayload)
}

// base58Encode encodes data in Base58.
func base58Encode(input []byte) string {
	var result []byte
	x := new(big.Int).SetBytes(input)

	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Preserve leading zeros
	for _, b := range input {
		if b != 0x00 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// base58Decode decodes Base58 data.
func base58Decode(input string) []byte {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, char := range []byte(input) {
		value := bytes.IndexByte(base58Alphabet, char)
		if value == -1 {
			panic("Invalid Base58 character")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(value)))
	}

	decoded := result.Bytes()

	// Add leading zeros
	leadingZeros := 0
	for _, char := range []byte(input) {
		if char != base58Alphabet[0] {
			break
		}
		leadingZeros++
	}

	return append(make([]byte, leadingZeros), decoded...)
}

// checksum calculates a checksum for a payload.
func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}
