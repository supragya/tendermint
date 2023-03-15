package mstm

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	gnarkeddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/tendermint/tendermint/types"
)

const MSTM_MAXVALIDATORS int = 150

func GenerateLightHeader(block *types.Block, validators *types.ValidatorSet) *types.HeaderAux {
	hasher := mimc.NewMiMC()

	// Generate MiMC hash for AppHash (so it accomodates within
	// fr.Element)
	appHashFrElem := fr.NewElement(0)
	hasher.Write(block.AppHash.Bytes())
	appHashFrElem.SetBytes(hasher.Sum([]byte{}))

	// Generate MiMC hash for ValidatorsHash (so it accomodates
	// within fr.Element)
	hasher.Reset()
	for i := 0; i < MSTM_MAXVALIDATORS; i++ {
		_, validator := validators.GetByIndex(int32(i))
		var (
			valX, valY = fr.NewElement(0), fr.NewElement(0)
			valPow     = fr.NewElement(0)
		)
		if validator != nil {
			pkauxBytes := validator.PubKeyAux.Bytes()
			eddsaPubKey := gnarkeddsa.PublicKey{}
			_, err := eddsaPubKey.SetBytes(pkauxBytes)
			if err != nil {
				panic(err)
			}
			valPow.SetInt64(validator.VotingPower)
			valX, valY = eddsaPubKey.A.X, eddsaPubKey.A.Y
		}

		// Generates bytes
		valXBytes, valYBytes, valPowBytes := valX.Bytes(), valY.Bytes(), valPow.Bytes()
		hasher.Write(valXBytes[:])
		hasher.Write(valYBytes[:])
		hasher.Write(valPowBytes[:])
	}
	valHashFrElem := fr.NewElement(0)
	valHashFrElem.SetBytes(hasher.Sum([]byte{}))

	// Encode time (unix seconds)
	timeFrElem := fr.NewElement(0)
	timeFrElem.SetInt64(block.Time.Unix())

	// Encode height
	heightFrElem := fr.NewElement(0)
	heightFrElem.SetInt64(block.Height)

	return &types.HeaderAux{
		AppHash:        appHashFrElem,
		ValidatorsHash: valHashFrElem,
		Time:           timeFrElem,
		Height:         heightFrElem,
	}
}

func GenerateHeaderAuxHash(headerAux *types.HeaderAux) fr.Element {
	hasher := mimc.NewMiMC()

	bytes := headerAux.AppHash.Bytes()
	hasher.Write(bytes[:])

	bytes = headerAux.ValidatorsHash.Bytes()
	hasher.Write(bytes[:])

	bytes = headerAux.Time.Bytes()
	hasher.Write(bytes[:])

	bytes = headerAux.Height.Bytes()
	hasher.Write(bytes[:])

	elem := fr.NewElement(0)
	elem.SetBytes(hasher.Sum([]byte{}))
	return elem
}
