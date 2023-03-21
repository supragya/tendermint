package types

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// HeaderAux defines SNARK friendly header for
// multisig tendermint
type HeaderAux struct {
	AppHash        fr.Element
	ValidatorsHash fr.Element
	Time           fr.Element
	Height         fr.Element
}
