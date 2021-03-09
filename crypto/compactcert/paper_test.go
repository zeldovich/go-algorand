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
	"math"
	"os"
	"sort"
	"testing"
	"time"

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

func paperCertSize(t *testing.T, npart int, provenWeightPct int, signedWeightPct int, mulpower int) (int, int, int) {
	mul := 1.0 - math.Pow(0.1, float64(mulpower))
	if mulpower == 0 { // Special case, not continuous..
		mul = 1.0
	}

	partWeights := make([]uint64, npart)
	partWeights[0] = 1 << 44
	totalWeight := partWeights[0]
	for i := 1; i < npart; i++ {
		partWeights[i] = uint64(float64(partWeights[i-1]) * mul)
		if partWeights[i] == 0 {
			partWeights[i] = 1
		}

		if totalWeight+partWeights[i] < totalWeight {
			t.Error("weight overflow")
		}

		totalWeight += partWeights[i]
	}

	// fmt.Printf("mul: %f (1-10^-%d)\n", mul, mulpower)
	// fmt.Printf("  total weight %d\n", totalWeight)
	// fmt.Printf("highest weight %d\n", partWeights[0])
	// fmt.Printf(" lowest weight %d\n", partWeights[npart-1])

	provenWeight := totalWeight / 100 * uint64(provenWeightPct)
	signedWeight := totalWeight / 100 * uint64(signedWeightPct)

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
			Weight: partWeights[i],
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

	// XXX for skew, this takes the highest signers first.
	// But for the skew graph we anyway have signedWeight=100%.
	var sigWeight uint64
	var naiveSigCount int
	for i := 0; i < npart && sigWeight < signedWeight; i++ {
		err = b.Add(uint64(i), sigs[i], false)
		require.NoError(t, err)
		if sigWeight < provenWeight {
			naiveSigCount += 1
		}
		sigWeight += parts[i].Weight
	}

	cert, err := b.Build()
	require.NoError(t, err)

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err)

	return len(protocol.Encode(cert)), len(cert.Reveals), naiveSigCount
}

func paperVerifyTime(t *testing.T, npart int, provenWeightPct int, signedWeightPct int, mulpower int) time.Duration {
	mul := 1.0 - math.Pow(0.1, float64(mulpower))
	if mulpower == 0 { // Special case, not continuous..
		mul = 1.0
	}

	partWeights := make([]uint64, npart)
	partWeights[0] = 1 << 44
	totalWeight := partWeights[0]
	for i := 1; i < npart; i++ {
		partWeights[i] = uint64(float64(partWeights[i-1]) * mul)
		if partWeights[i] == 0 {
			partWeights[i] = 1
		}

		if totalWeight+partWeights[i] < totalWeight {
			t.Error("weight overflow")
		}

		totalWeight += partWeights[i]
	}

	// fmt.Printf("mul: %f (1-10^-%d)\n", mul, mulpower)
	// fmt.Printf("  total weight %d\n", totalWeight)
	// fmt.Printf("highest weight %d\n", partWeights[0])
	// fmt.Printf(" lowest weight %d\n", partWeights[npart-1])

	provenWeight := totalWeight / 100 * uint64(provenWeightPct)
	signedWeight := totalWeight / 100 * uint64(signedWeightPct)

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
			Weight: partWeights[i],
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

	// XXX for skew, this takes the highest signers first
	var sigWeight uint64
	for i := 0; i < npart && sigWeight < signedWeight; i++ {
		err = b.Add(uint64(i), sigs[i], false)
		require.NoError(t, err)
		sigWeight += parts[i].Weight
	}

	cert, err := b.Build()
	require.NoError(t, err)

	verif := MkVerifier(param, partcom.Root())

	t0 := time.Now()
	niter := 100
	for i := 0; i < niter; i++ {
		err = verif.Verify(cert)
		require.NoError(t, err)
	}
	t1 := time.Now()

	return t1.Sub(t0) / time.Duration(niter)
}

func median(elems []int) int {
	sort.Ints(elems)
	return elems[len(elems)/2]
}

func medianDuration(elems []time.Duration) time.Duration {
	sort.Slice(elems, func(i, j int) bool { return elems[i] < elems[j] })
	return elems[len(elems)/2]
}

func medianCertSize(t *testing.T, npart int, provenWeightPct int, signedWeightPct int, mulpower int) (int, int, int) {
	var reveals []int
	var sizes []int
	var naiveSigCounts []int
	for i := 0; i < 3; i++ {
		sz, nr, naiveSigCount := paperCertSize(t, npart, provenWeightPct, signedWeightPct, mulpower)
		sizes = append(sizes, sz)
		reveals = append(reveals, nr)
		naiveSigCounts = append(naiveSigCounts, naiveSigCount)
	}
	return median(sizes), median(reveals), median(naiveSigCounts)
}

func medianVerifyTime(t *testing.T, npart int, provenWeightPct int, signedWeightPct int, mulpower int) time.Duration {
	var times []time.Duration
	for i := 0; i < 3; i++ {
		t := paperVerifyTime(t, npart, provenWeightPct, signedWeightPct, mulpower)
		times = append(times, t)
	}
	return medianDuration(times)
}

func TestPaperCertSizes(t *testing.T) {
	f, err := os.Create("certsize.csv")
	require.NoError(t, err)
	defer f.Close()

	csv := csv.NewWriter(f)
	defer csv.Flush()

	provenWeightPct := 50
	mulpower := 0

	csv.Write([]string{"signedWeight", "provenWeight", "skew", "certBytes", "certReveals", "npart"})

	for _, npart := range([]int{1000*1000, 10*1000, 100}) {
		for sigpct := provenWeightPct + 5; sigpct <= 100; sigpct += 5 {
			sz, nr, _ := medianCertSize(t, npart, provenWeightPct, sigpct, mulpower)
			csv.Write([]string{
				fmt.Sprintf("%d", sigpct),
				fmt.Sprintf("%d", provenWeightPct),
				fmt.Sprintf("%d", mulpower),
				fmt.Sprintf("%d", sz),
				fmt.Sprintf("%d", nr),
				fmt.Sprintf("%d", npart),
			})
		}
	}

	for _, provenWeightPct := range([]int{10, 30, 70}) {
		npart := 1000*1000
		for sigpct := provenWeightPct + 5; sigpct <= 100; sigpct += 5 {
			sz, nr, _ := medianCertSize(t, npart, provenWeightPct, sigpct, mulpower)
			csv.Write([]string{
				fmt.Sprintf("%d", sigpct),
				fmt.Sprintf("%d", provenWeightPct),
				fmt.Sprintf("%d", mulpower),
				fmt.Sprintf("%d", sz),
				fmt.Sprintf("%d", nr),
				fmt.Sprintf("%d", npart),
			})
		}
	}
}

func TestPaperCertSizeSkew(t *testing.T) {
	f, err := os.Create("certskew.csv")
	require.NoError(t, err)
	defer f.Close()

	csv := csv.NewWriter(f)
	defer csv.Flush()

	npart := 1000 * 1000
	provenWeightPct := 50
	sigpct := 100

	csv.Write([]string{"signedWeight", "skew", "certBytes", "certReveals", "naiveSigCount"})

	for mulpower := 1; mulpower < 10; mulpower++ {
		sz, nr, naiveSigCount := medianCertSize(t, npart, provenWeightPct, sigpct, mulpower)
		csv.Write([]string{
			fmt.Sprintf("%d", sigpct),
			fmt.Sprintf("%d", mulpower),
			fmt.Sprintf("%d", sz),
			fmt.Sprintf("%d", nr),
			fmt.Sprintf("%d", naiveSigCount),
		})
	}
}

func TestPaperVerifyTime(t *testing.T) {
	f, err := os.Create("verifytime.csv")
	require.NoError(t, err)
	defer f.Close()

	csv := csv.NewWriter(f)
	defer csv.Flush()

	provenWeightPct := 50
	mulpower := 0

	csv.Write([]string{"signedWeight", "npart", "verifyTime"})

	for _, npart := range([]int{1000*1000, 10*1000, 100}) {
		for sigpct := 55; sigpct <= 100; sigpct += 5 {
			t := medianVerifyTime(t, npart, provenWeightPct, sigpct, mulpower)
			csv.Write([]string{
				fmt.Sprintf("%d", sigpct),
				fmt.Sprintf("%d", npart),
				fmt.Sprintf("%d", t.Nanoseconds()),
			})
		}
	}
}

type NaiveCertEntry struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PK  crypto.PublicKey `codec:"p"`
	Sig crypto.Signature `codec:"s"`
}

func TestPaperFlow(t *testing.T) {
	mul := 1.0
	npart := 1000000
	provenWeightPct := 50
	signedWeightPct := 100

	partWeights := make([]uint64, npart)
	partWeights[0] = 1 << 44
	totalWeight := partWeights[0]
	for i := 1; i < npart; i++ {
		partWeights[i] = uint64(float64(partWeights[i-1]) * mul)
		if partWeights[i] == 0 {
			partWeights[i] = 1
		}

		if totalWeight+partWeights[i] < totalWeight {
			t.Error("weight overflow")
		}

		totalWeight += partWeights[i]
	}

	provenWeight := totalWeight / 100 * uint64(provenWeightPct)
	signedWeight := totalWeight / 100 * uint64(signedWeightPct)

	param := Params{
		Msg:          TestMessage("hello world"),
		ProvenWeight: uint64(provenWeight),
		SecKQ:        128,
	}

	var keys []*crypto.SignatureSecrets
	for i := 0; i < npart; i++ {
		var seed crypto.Seed
		crypto.RandBytes(seed[:])
		key := crypto.GenerateSignatureSecrets(seed)
		keys = append(keys, key)
	}

	var parts []Participant
	for i := 0; i < npart; i++ {
		part := Participant{
			PK:     keys[i].SignatureVerifier,
			Weight: partWeights[i],
		}

		parts = append(parts, part)
	}

	var sigs []crypto.Signature
	t0 := time.Now()
	for i := 0; i < npart; i++ {
		sig := keys[i].Sign(param.Msg)
		sigs = append(sigs, sig)
	}
	t1 := time.Now()
	fmt.Printf("Signing time: %v\n", t1.Sub(t0))

	partcom, err := merklearray.Build(PartCommit{parts})
	require.NoError(t, err)

	t2 := time.Now()
	b, err := MkBuilder(param, parts, partcom)
	require.NoError(t, err)

	// XXX for skew, this takes the highest signers first
	var sigWeight uint64
	t3 := time.Now()
	for i := 0; i < npart && sigWeight < signedWeight; i++ {
		err = b.Add(uint64(i), sigs[i], true)
		require.NoError(t, err)
		sigWeight += parts[i].Weight
	}
	t4 := time.Now()

	cert, err := b.Build()
	require.NoError(t, err)
	t5 := time.Now()
	fmt.Printf("Cert build time: %v\n", t5.Sub(t2))
	fmt.Printf("Sig verify time: %v\n", t4.Sub(t3))

	t6 := time.Now()
	sigWeight = 0
	naiveCert := make(map[uint64]NaiveCertEntry)
	for i := 0; i < npart && sigWeight < provenWeight; i++ {
		ok := parts[i].PK.Verify(param.Msg, sigs[i])
		require.True(t, ok)
		sigWeight += parts[i].Weight
		naiveCert[uint64(i)] = NaiveCertEntry{
			PK:  parts[i].PK,
			Sig: sigs[i],
		}
	}
	t7 := time.Now()
	fmt.Printf("Naive build time: %v\n", t7.Sub(t6))
	fmt.Printf("Naive cert size: %d bytes\n", len(protocol.EncodeReflect(naiveCert)))

	sigWeight = 0
	naiveCert = make(map[uint64]NaiveCertEntry)
	for i := 0; i < npart && sigWeight < provenWeight/100; i++ {
		ok := parts[i].PK.Verify(param.Msg, sigs[i])
		require.True(t, ok)
		sigWeight += parts[i].Weight
		naiveCert[uint64(i)] = NaiveCertEntry{
			PK:  parts[i].PK,
			Sig: sigs[i],
		}
	}
	fmt.Printf("10K naive cert size: %d bytes\n", len(protocol.EncodeReflect(naiveCert)))

	sigWeight = 0
	naiveCert = make(map[uint64]NaiveCertEntry)
	for i := 0; i < npart && sigWeight < provenWeight/10000; i++ {
		ok := parts[i].PK.Verify(param.Msg, sigs[i])
		require.True(t, ok)
		sigWeight += parts[i].Weight
		naiveCert[uint64(i)] = NaiveCertEntry{
			PK:  parts[i].PK,
			Sig: sigs[i],
		}
	}
	fmt.Printf("100 naive cert size: %d bytes\n", len(protocol.EncodeReflect(naiveCert)))

	verif := MkVerifier(param, partcom.Root())
	err = verif.Verify(cert)
	require.NoError(t, err)
}
