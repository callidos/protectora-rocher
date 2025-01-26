// Code généré à partir des templates. NE PAS MODIFIER.

package communication

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"crypto/rand"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

// HexBytes représente un []byte encodé en hex pour JSON
type HexBytes []byte

func (b HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

func (b *HexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(s)
	return err
}

func Gunzip(in []byte) ([]byte, error) {
	buf := bytes.NewBuffer(in)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func ReadGzip(path string) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Gunzip(buf)
}

func TestDilithium(t *testing.T) {
	for _, sub := range []string{"keyGen", "sigGen", "sigVer"} {
		t.Run(sub, func(t *testing.T) {
			testDilithium(t, sub)
		})
	}
}

func testDilithium(t *testing.T, sub string) {
	buf, err := ReadGzip("../testdata/Dilithium-" + sub + "/prompt.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var prompt struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err = json.Unmarshal(buf, &prompt); err != nil {
		t.Fatal(err)
	}

	buf, err = ReadGzip("../testdata/Dilithium-" + sub + "/expectedResults.json.gz")
	if err != nil {
		t.Fatal(err)
	}

	var results struct {
		TestGroups []json.RawMessage `json:"testGroups"`
	}

	if err := json.Unmarshal(buf, &results); err != nil {
		t.Fatal(err)
	}

	rawResults := make(map[int]json.RawMessage)

	for _, rawGroup := range results.TestGroups {
		var abstractGroup struct {
			Tests []json.RawMessage `json:"tests"`
		}
		if err := json.Unmarshal(rawGroup, &abstractGroup); err != nil {
			t.Fatal(err)
		}
		for _, rawTest := range abstractGroup.Tests {
			var abstractTest struct {
				TcID int `json:"tcId"`
			}
			if err := json.Unmarshal(rawTest, &abstractTest); err != nil {
				t.Fatal(err)
			}
			rawResults[abstractTest.TcID] = rawTest
		}
	}

	switch sub {
	case "keyGen":
		performKeyGeneration(t)
	case "sigGen":
		performSignatureGeneration(t)
	case "sigVer":
		performSignatureVerification(t)
	}
}

func performKeyGeneration(t *testing.T) {
	pk, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clés: %v", err)
	}
	t.Logf("Clé publique: %x\n", pk.Bytes())
	t.Logf("Clé privée: %x\n", sk.Bytes())
}

func performSignatureGeneration(t *testing.T) {
	_, sk, _ := mode2.GenerateKey(rand.Reader)
	message := []byte("Message à signer")
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(sk, message, signature)
	t.Logf("Signature: %x\n", signature)
}

func performSignatureVerification(t *testing.T) {
	pk, sk, _ := mode2.GenerateKey(rand.Reader)
	message := []byte("Message à signer")
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(sk, message, signature)

	if mode2.Verify(pk, message, signature) {
		t.Log("Signature validée avec succès.")
	} else {
		t.Fatal("La signature est invalide.")
	}
}
