// Copyright (C) 2019-2023 Algorand, Inc.
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

package test

import (
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func FuzzCanonicalDecode(f *testing.F) {
	var t CanonicalTestStruct
	f.Add(protocol.Encode(&t))

	t.I = 1
	f.Add(protocol.Encode(&t))

	t.I = -1
	f.Add(protocol.Encode(&t))

	t.I = 1<<8
	f.Add(protocol.Encode(&t))

	t.I = -(1<<8)
	f.Add(protocol.Encode(&t))

	t.I = 1<<16
	f.Add(protocol.Encode(&t))

	t.I = -(1<<16)
	f.Add(protocol.Encode(&t))

	t.I = (1<<32)
	f.Add(protocol.Encode(&t))

	t.I = -(1<<32)
	f.Add(protocol.Encode(&t))

	t.H = 1
	t.I = 1
	f.Add(protocol.Encode(&t))

	for i := 0; i < 16; i++ {
		protocol.RandomizeObject(&t)
		f.Add(protocol.Encode(&t))
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		var dt CanonicalTestStruct
		err := protocol.Decode(msg, &dt)
		if err != nil {
			// Decoding failure, which might later include errors
			// due to the input msg being non-canonical.
			return
		}

		msg2 := protocol.Encode(&dt)
		require.Equal(t, msg, msg2)
	})
}
