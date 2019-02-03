package u2fkey

import (
	"crypto/sha256"
	"testing"
)

func TestGenerateAndUseKey(t *testing.T) {
	k, err := GenerateKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	digest := sha256.Sum256([]byte("Hello, World!"))
	sig, err := k.Sign(nil, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	res := Verify(k.pubKey, digest[:], sig)
	if !res {
		t.Error("Could not verify signature")
	}
}

func TestLoadAndUseKey(t *testing.T) {
	k, err := GenerateKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	k, err = LoadKey("example.com", k.KeyHandle, k.pubKey.EcdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	digest := sha256.Sum256([]byte("Hello, World!"))
	sig, err := k.Sign(nil, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	res := Verify(k.pubKey, digest[:], sig)
	if !res {
		t.Error("Could not verify signature")
	}
}

func TestNegativeVerify(t *testing.T) {
	k, err := GenerateKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	digest := sha256.Sum256([]byte("Hello, World!"))
	sig, err := k.Sign(nil, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	res := Verify(k.pubKey, digest[:], sig)
	if !res {
		t.Error("Could not verify signature")
	}

	badDigest := sha256.Sum256([]byte("Goodbye, World!"))

	t.Run("Bad digest", func(t *testing.T) {
		res := Verify(k.pubKey, badDigest[:], sig)
		if res {
			t.Error("Verification should have failed on bad digest")
		}
	})

	t.Run("Bad signing key", func(t *testing.T) {
		u, err := GenerateKey("example.com")
		if err != nil {
			t.Fatal(err)
		}
		sig, err := u.Sign(nil, digest[:], nil)
		if err != nil {
			t.Fatal(err)
		}

		res := Verify(k.pubKey, digest[:], sig)
		if res {
			t.Error("Verification should have failed on bad origin")
		}
	})

	t.Run("Bad verifying key", func(t *testing.T) {
		u, err := GenerateKey("example.com")
		if err != nil {
			t.Fatal(err)
		}

		res := Verify(u.pubKey, digest[:], sig)
		if res {
			t.Error("Verification should have failed on bad origin")
		}
	})
}
