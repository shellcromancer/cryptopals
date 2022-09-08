package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path"
	"strings"
	"testing"
)

func TestEx01(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	expectedOutput := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if HexToBase64(input) != expectedOutput {
		t.Fatal("Mismatch output for Set01 - Ex 1")
	}
}

func TestEx02(t *testing.T) {
	result, err := PairXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}

	if result != "746865206b696420646f6e277420706c6179" {
		t.Fatal("Mismatched output for Set01 - Ex 2")
	}
}

func TestEx03(t *testing.T) {
	result, key, score := DecryptXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	t.Logf("The key was 0x%x (fitting quotient=%f): %q", key, score, result)
}

func TestEx04(t *testing.T) {
	input, err := os.ReadFile(path.Join("testdata", "04.txt"))
	if err != nil {
		t.Fatal(err)
	}
	tests := strings.Split(string(input), "\n")

	var plaintexts []string
	for _, tt := range tests {
		plaintext, isXORd := IsSingleByteXOR(tt)

		if isXORd {
			plaintexts = append(plaintexts, plaintext)
		}
	}

	if len(plaintexts) != 1 {
		t.Error("Got wrong number of plaintexts")
	}

	t.Logf("Got %d possible XORd ciphertext(s): %v", len(plaintexts), strings.Join(plaintexts, ", "))
}

func TestEx05(t *testing.T) {
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	key := "ICE"

	ciphertext := EncryptReapeatingXOR([]byte(input), []byte(key))

	result := hex.EncodeToString(ciphertext)
	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	if result != expected {
		t.Errorf("Mismatched result: got=(%s) expected(%s)", result, expected)
	}
}

func TestEx06(t *testing.T) {
	input, err := os.ReadFile(path.Join("testdata", "06.txt"))
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}

	_, key := BreakRepeatingKeyXOR(ciphertext)
	t.Logf("probable key length is %d bytes", key)
}

func TestHammingDistance(t *testing.T) {
	dist := hammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	expectedDistance := 37
	if dist != expectedDistance {
		t.Fatalf("wrong distance. got=(%d) expected=(%d)", dist, expectedDistance)
	}
}
