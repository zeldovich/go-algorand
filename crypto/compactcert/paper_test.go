// Copyright (C) 2019-2021 Algorand, Inc.
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
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/protocol"

	"github.com/stretchr/testify/require"
)

func TestPaperCertSizeBreakdown(t *testing.T) {
	totalWeight := 10 * 1000 * 1000
	npart := 1 * 1000 * 1000

	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(totalWeight / 2),
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	key := crypto.GenerateSignatureSecrets(seed)

	var parts []Participant
	for i := 0; i < npart; i++ {
		part := Participant{
			PK:     key.SignatureVerifier,
			Weight: uint64(totalWeight / npart),
		}

		parts = append(parts, part)
	}

	sig := key.Sign(param.Msg)

	var sigs []crypto.Signature
	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.Build(PartCommit{parts})
	require.NoError(t, err)

	b, err := MkBuilder(param, parts, partcom)
	require.NoError(t, err)

	for i := 0; i < npart; i++ {
		err = b.Add(uint64(i), sigs[i], false)
		require.NoError(t, err)
	}

	cert, err := b.Build()
	require.NoError(t, err)

	var someReveal Reveal
	for _, rev := range cert.Reveals {
		someReveal = rev
		break
	}

	certenc := protocol.Encode(cert)
	fmt.Printf("Cert size with 100%% signatures:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(cert.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(cert.SigProofs))/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", len(protocol.Encode(&someReveal.SigSlot)))
	fmt.Printf("    %6d bytes reveals[*] total\n", len(protocol.Encode(&someReveal)))
	fmt.Printf("  %6d bytes total\n", len(certenc))

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err)
}

func paperCertSize(t *testing.T, totalWeight int, npart int, provenWeight int, signedWeight int) (int, int) {
	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(provenWeight),
		SecKQ:        128,
	}

	// Share the key; we allow the same vote key to appear in multiple accounts..
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	key := crypto.GenerateSignatureSecrets(seed)

	var parts []Participant
	for i := 0; i < npart; i++ {
		part := Participant{
			PK:     key.SignatureVerifier,
			Weight: uint64(totalWeight / npart),
		}

		parts = append(parts, part)
	}

	sig := key.Sign(param.Msg)

	var sigs []crypto.Signature
	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.Build(PartCommit{parts})
	require.NoError(t, err)

	b, err := MkBuilder(param, parts, partcom)
	require.NoError(t, err)

	var sigWeight int
	for i := 0; i < npart && sigWeight < signedWeight; i++ {
		err = b.Add(uint64(i), sigs[i], false)
		require.NoError(t, err)
		sigWeight += int(parts[i].Weight)
	}

	cert, err := b.Build()
	require.NoError(t, err)

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err)

	return len(protocol.Encode(cert)), len(cert.Reveals)
}

func median(elems []int) int {
	sort.Ints(elems)
	return elems[len(elems)/2]
}

func medianCertSize(t *testing.T, totalWeight int, npart int, provenWeight int, signedWeight int) (int, int) {
	var nr int
	var sizes []int
	for i := 0; i < 3; i++ {
		var sz int
		sz, nr = paperCertSize(t, totalWeight, npart, provenWeight, signedWeight)
		sizes = append(sizes, sz)
	}
	return median(sizes), nr
}

// Generate certsize.csv
func TestPaperCertSizes(t *testing.T) {
	csv := csv.NewWriter(os.Stdout)

	totalWeight := 10 * 1000 * 1000
	npart := 1000 * 1000
	provenWeight := 5 * 1000 * 1000

	csv.Write([]string{"signedWeight", "certBytes", "certReveals"})

	for sigpct := 55; sigpct <= 100; sigpct += 5 {
		sz, nr := medianCertSize(t, totalWeight, npart, provenWeight, totalWeight / 100 * sigpct)
		csv.Write([]string{
			fmt.Sprintf("%d", sigpct),
			fmt.Sprintf("%d", sz),
			fmt.Sprintf("%d", nr),
		})
	}

	csv.Flush()
}
