package u2fkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/u2f/u2fhid"
	"crypto/u2f/u2ftoken"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"
)

type U2fKey struct {
	pubKey    *PublicKey
	KeyHandle []byte
	token     *u2ftoken.Token
}

func (k *U2fKey) Close() {
}

type PublicKey struct {
	EcdsaKey *ecdsa.PublicKey
	App      []byte
}

func openFirstToken() (*u2ftoken.Token, error) {
	devices, err := u2fhid.Devices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, errors.New("no U2F tokens found")
	}
	d := devices[0]

	dev, err := u2fhid.Open(d)
	if err != nil {
		return nil, err
	}
	t := u2ftoken.NewToken(dev)

	return t, nil
}

func GenerateKey(origin string) (*U2fKey, error) {
	t, err := openFirstToken()
	if err != nil {
		return nil, err
	}

	challenge := make([]byte, 32)
	app := sha256.Sum256([]byte(origin))

	var res []byte
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app[:]})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return nil, err
		}
		break
	}

	x := big.NewInt(0)
	x.SetBytes(res[2:34])
	y := big.NewInt(0)
	y.SetBytes(res[34:66])
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	khLen := int(res[66])
	keyHandle := res[67 : 67+khLen]

	return &U2fKey{
		pubKey: &PublicKey{
			EcdsaKey: pubKey,
			App:      app[:],
		},
		KeyHandle: keyHandle,
		token:     t,
	}, nil
}

func LoadKey(origin string, keyHandle []byte, pubKey *ecdsa.PublicKey) (*U2fKey, error) {
	t, err := openFirstToken()
	if err != nil {
		return nil, err
	}
	app := sha256.Sum256([]byte(origin))
	return &U2fKey{
		pubKey: &PublicKey{
			EcdsaKey: pubKey,
			App:      app[:],
		},
		KeyHandle: keyHandle,
		token:     t,
	}, nil
}

func (k *U2fKey) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *U2fKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	req := u2ftoken.AuthenticateRequest{
		Challenge:   digest,
		Application: k.pubKey.App,
		KeyHandle:   k.KeyHandle,
	}

	var err error
	var res *u2ftoken.AuthenticateResponse
	for {
		res, err = k.token.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			return nil, err
		}
		break
	}
	return res.RawResponse, nil
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pubKey *PublicKey, digest []byte, rawAuth []byte) bool {
	payload := make([]byte, 0, 69)
	payload = append(payload, pubKey.App...)
	payload = append(payload, rawAuth[0:5]...)
	payload = append(payload, digest...)

	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(rawAuth[5:], &sig)
	if err != nil {
		return false
	}

	u2fDigest := sha256.Sum256(payload)

	return ecdsa.Verify(pubKey.EcdsaKey, u2fDigest[:], sig.R, sig.S)
}
