package eddsabn254

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/tendermint/tendermint/crypto"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

//-------------------------------------

var (
	_ crypto.PrivKey = PrivKey{}
)

const (
	PrivKeyName = "tendermint/PrivKeyEddsabn254"
	PubKeyName  = "tendermint/PubKeyEddsabn254"
	// PubKeySize is is the size, in bytes, of public keys as used in this package.
	PubKeySize = fr.Bytes
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 2*fr.Bytes + 32
	// Size of an Edwards25519 signature. Namely the size of a compressed
	// Edwards25519 point, and a field element. Both of which are 32 bytes.
	SignatureSize = 2 * fr.Bytes

	KeyType = "eddsabn254"
)

func init() {
	tmjson.RegisterType(PubKey{}, PubKeyName)
	tmjson.RegisterType(PrivKey{}, PrivKeyName)
}

// PrivKey implements crypto.PrivKey.
type PrivKey struct {
	internal eddsa.PrivateKey
}

// TypeTag satisfies the jsontypes.Tagged interface.
func (PrivKey) TypeTag() string { return PrivKeyName }

func (pk PrivKey) MarshalJSON() ([]byte, error) {
	privKeyBytes := pk.Bytes()
	encodedPKBytes := base64.StdEncoding.EncodeToString(privKeyBytes)
	return []byte(fmt.Sprintf("\"%s\"", encodedPKBytes)), nil
}

func (pk *PrivKey) UnmarshalJSON(data []byte) error {
	encoded := strings.Trim(string(data), "\"")
	privKeyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	if _, err := pk.internal.SetBytes(privKeyBytes); err != nil {
		return err
	}
	return nil
}

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
	return privKey.internal.Bytes()
}

// Sign produces a signature on the provided message.
// This assumes the privkey is wellformed in the golang format.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	return privKey.internal.Sign(msg, mimc.NewMiMC())
}

// PubKey gets the corresponding public key from the private key.
//
// Panics if the private key is not initialized.
func (privKey PrivKey) PubKey() crypto.PubKey {
	return PubKey{
		Internal: privKey.internal.PublicKey,
	}
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if other, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey.Bytes()[:], other.Bytes()[:]) == 1
	}

	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

// GenPrivKey generates a new eddsa private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKey {
	eddsaKey, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return PrivKey{
		internal: *eddsaKey,
	}
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKey {
	var k PrivKey
	seed := sha256.Sum256(secret)
	_, err := rand.Read(seed[:])
	if err != nil {
		panic(err)
	}
	return k
}

//-------------------------------------

var _ crypto.PubKey = PubKey{}

// PubKeyEddsa implements crypto.PubKey for the Eddsa signature scheme.
type PubKey struct {
	Internal eddsa.PublicKey
}

func (pk PubKey) MarshalJSON() ([]byte, error) {
	pubKeyBytes := pk.Bytes()
	encodedPKBytes := base64.StdEncoding.EncodeToString(pubKeyBytes)
	return []byte(fmt.Sprintf("\"%s\"", encodedPKBytes)), nil
}

func (pk *PubKey) UnmarshalJSON(data []byte) error {
	encoded := strings.Trim(string(data), "\"")
	pubKeyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	if _, err := pk.Internal.SetBytes(pubKeyBytes); err != nil {
		return err
	}
	return nil
}

func (pubKey *PubKey) ValidateBasic() error {
	nilFrElem := fr.NewElement(0)
	if pubKey.Internal.A.X.Cmp(&nilFrElem) == 0 ||
		pubKey.Internal.A.Y.Cmp(&nilFrElem) == 0 {
		return errors.New("invalid pubkey: unset X or Y coordinate")
	}
	return nil
}

// TypeTag satisfies the jsontypes.Tagged interface.
func (PubKey) TypeTag() string { return PubKeyName }

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	return crypto.AddressHash(pubKey.Bytes())
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return pubKey.Internal.Bytes()
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	result, err := pubKey.Internal.Verify(sig, msg, mimc.NewMiMC())
	if err != nil {
		fmt.Printf("msg and sig len %v %v\n", len(msg), len(sig))
		return false
	}
	return result
}

func (pubKey PubKey) Type() string {
	return KeyType
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if other, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey.Bytes(), other.Bytes())
	}

	return false
}
