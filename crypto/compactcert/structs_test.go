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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func TestSigSlotCommitHash(t *testing.T) {
	var ssc sigslotCommit
	crypto.RandBytes(ssc.Sig[:])
	ssc.L = crypto.RandUint64()
	require.Equal(t, crypto.HashObj(&ssc), ssc.Hash())
}

func TestParticipantHash(t *testing.T) {
	var p Participant
	crypto.RandBytes(p.PK[:])
	p.Weight = crypto.RandUint64()
	require.Equal(t, crypto.HashObj(&p), p.Hash())
}
