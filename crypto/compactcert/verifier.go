// Copyright (C) 2019-2020 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package compactcert

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
)

// Verifier is used to verify a compact certificate.
type Verifier struct {
	Params

	partcom crypto.Digest
}

// MkVerifier constructs a verifier to check the compact certificate
// on the message specified in p, with partcom specifying the Merkle
// root of the participants that must sign the message.
func MkVerifier(p Params, partcom crypto.Digest) *Verifier {
	return &Verifier{
		Params:  p,
		partcom: partcom,
	}
}

// Verify checks if c is a valid compact certificate for the message
// and participants that were used to construct the Verifier.
func (v *Verifier) Verify(c *Cert) error {
<<<<<<< HEAD
	if c.SignedWeight < v.ProvenWeight {
		return fmt.Errorf("cert signed weight %d < proven weight %d", c.SignedWeight, v.ProvenWeight)
=======
	if c.SignedWeight <= v.ProvenWeight {
		return fmt.Errorf("cert signed weight %d <= proven weight %d", c.SignedWeight, v.ProvenWeight)
>>>>>>> origin/master
	}

	// Verify all of the reveals
	sigs := make(map[uint64]crypto.Hashable)
	parts := make(map[uint64]crypto.Hashable)
<<<<<<< HEAD
	for i, r := range c.Reveals {
		_, ok := sigs[r.Pos]
		if ok {
			return fmt.Errorf("duplicate reveal for %d", r.Pos)
		}

		sigs[r.Pos] = r.SigSlot
		parts[r.Pos] = r.Part

		ephID := basics.OneTimeIDForRound(v.SigRound, r.Part.KeyDilution)
		if !r.Part.PK.Verify(ephID, v.Msg, r.SigSlot.Sig.OneTimeSignature) {
			return fmt.Errorf("signature in reveal %d does not verify", i)
=======
	for pos, r := range c.Reveals {
		sigs[pos] = r.SigSlot
		parts[pos] = r.Part

		ephID := basics.OneTimeIDForRound(v.SigRound, r.Part.KeyDilution)
		if !r.Part.PK.Verify(ephID, v.Msg, r.SigSlot.Sig.OneTimeSignature) {
			return fmt.Errorf("signature in reveal pos %d does not verify", pos)
>>>>>>> origin/master
		}
	}

	err := merklearray.Verify(c.SigCommit, sigs, c.SigProofs)
	if err != nil {
		return err
	}

	err = merklearray.Verify(v.partcom, parts, c.PartProofs)
	if err != nil {
		return err
	}

	// Verify that the reveals contain the right coins
	nr, err := v.numReveals(c.SignedWeight)
	if err != nil {
		return err
	}

	for j := uint64(0); j < nr; j++ {
		coin := hashCoin(j, c.SigCommit, c.SignedWeight)
		matchingReveal := false
		for _, r := range c.Reveals {
			if r.SigSlot.L <= coin && coin < r.SigSlot.L+r.Part.Weight {
				matchingReveal = true
				break
			}
		}

		if !matchingReveal {
			return fmt.Errorf("no reveal for coin %d at %d", j, coin)
		}
	}

	return nil
}
