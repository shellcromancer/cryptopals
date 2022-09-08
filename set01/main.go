package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"unicode"
)

func main() {
	fmt.Println("Stub main - Go run tests.")
}

func HexToBase64(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}

	return base64.RawStdEncoding.EncodeToString(data)
}

func PairXOR(s1, s2 string) (string, error) {
	if len(s1) != len(s2) {
		return "", fmt.Errorf("input strings must have same length")
	}

	d1, err := hex.DecodeString(s1)
	if err != nil {
		return "", fmt.Errorf("failed to decode s1: %w", err)
	}

	d2, err := hex.DecodeString(s2)
	if err != nil {
		return "", fmt.Errorf("failed to decode s2: %w", err)
	}

	result := make([]byte, len(d1))

	for i := range d1 {
		result[i] = d1[i] ^ d2[i]
	}

	return hex.EncodeToString(result), nil
}

func DecryptXOR(s string) (string, byte, float64) {
	d, err := hex.DecodeString(s)
	if err != nil {
		return "", 0x00, 0.00
	}

	minScore := 1.0
	var key byte
	var plaintext string

	for i := 0x00; i <= 0xff; i++ {
		k := byte(i)
		result := make([]byte, len(d))

		for i := range d {
			result[i] = d[i] ^ k
		}

		score := frequencyScore(result)
		if score <= minScore {
			// fmt.Printf("Better result: %f -> %f; %s => %s\n", minScore, score, plaintext, string(result))

			minScore = score
			key = k
			plaintext = string(result)
		}
	}

	return plaintext, key, minScore
}

// IsSingleByteXOR using a heuristic score to determine if some ciphertext is XOR'd
// with a single byte XOR key.
func IsSingleByteXOR(s string) (string, bool) {
	plaintext, _, score := DecryptXOR(s)

	return plaintext, score < 0.025
}

func frequencyScore(s []byte) float64 {
	goldenEnglish := map[byte]float64{
		'a': .0804,
		'b': .0148,
		'c': .0334,
		'd': .0382,
		'e': .1249,
		'f': .0240,
		'g': .0187,
		'h': .0505,
		'i': .0757,
		'j': .0016,
		'k': .0054,
		'l': .0407,
		'm': .0251,
		'n': .0723,
		'o': .0764,
		'p': .0214,
		'q': .0012,
		'r': .0628,
		's': .0651,
		't': .0928,
		'u': .0273,
		'v': .0105,
		'w': .0168,
		'x': .0023,
		'y': .0166,
		'z': .0009,
		' ': .2000,
	}

	charFreq := make(map[byte]float64)
	sz := 0.0
	for _, c := range s {
		r := rune(c)
		if c < 127 && (unicode.IsLetter(r) || c == 32) {
			r := unicode.ToLower(r)
			charFreq[byte(r)]++
			sz++
		}
	}

	// Handle space outside of range
	val, exists := charFreq[' ']
	if !exists {
		val = 0.0
	}
	charFreq[' '] = val / sz

	for i := 97; i <= 122; i++ {
		b := byte(i)

		val, exists := charFreq[b]
		if !exists {
			val = 0.0
		}

		charFreq[b] = val / sz
	}

	return fittingQuotient(goldenEnglish, charFreq)
}

// chiSquared test to compare frequencies to some expected set. Alternative algorithm
// to the fittingQuotient.
//
// nolint: deadcode, unused
func chiSquared(a, b map[byte]float64) float64 {
	return 0.00
}

// fittingQuotient is a measure of how well two frequency distributions match. The
// lower the value returned the closer a text frequency is expected to the english
// language.
func fittingQuotient(actual, expected map[byte]float64) float64 {
	if len(actual) != len(expected) {
		return 1.0
	}

	result := 0.0
	for i := range actual {
		result += math.Abs(expected[i] - actual[i])
	}
	return result / float64(len(actual))
}

func EncryptReapeatingXOR(plaintext []byte, key []byte) []byte {
	var w bytes.Buffer
	keyLen := len(key)

	for i, b := range plaintext {
		err := w.WriteByte(b ^ key[i%keyLen])
		if err != nil {
			return nil
		}
	}

	return w.Bytes()
}

// hammingDistance is a string edit metric that counts the number of differing bits
// between two strings/byte streams.
func hammingDistance(s1, s2 []byte) (result int) {
	if len(s1) != len(s2) {
		return math.MaxInt
	}

	for i := range s1 {
		result += bits.OnesCount8(s1[i] ^ s2[i])
	}

	return result
}

func BreakRepeatingKeyXOR(ciphertext []byte) (plaintext []byte, key byte) {
	const maxKeysize = 40

	var bestKeysize int
	smallestEdit := math.MaxInt

	for currKeysize := 2; currKeysize <= maxKeysize; currKeysize++ {
		chunk1 := ciphertext[0:currKeysize]
		chunk2 := ciphertext[currKeysize+1 : 2*currKeysize]

		normalizedEdit := hammingDistance(chunk1, chunk2) / currKeysize
		fmt.Printf("keysize %02d distance of %d\n", currKeysize, normalizedEdit)

		if normalizedEdit < smallestEdit {
			bestKeysize = currKeysize
			smallestEdit = normalizedEdit
		}
	}

	return nil, byte(bestKeysize)
}
