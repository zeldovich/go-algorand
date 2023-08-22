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

// This struct lives here so that msgp generates codec code for it.

type CanonicalTestStruct struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	A int64 `codec:"a,omitempty"`
	B struct {
		_struct struct{} `codec:",omitempty,omitemptyarray"`
		B1      bool     `codec:"b1,omitempty"`
		B2      string   `codec:"b2,omitempty"`
	} `codec:"b,omitempty"`
	C []byte    `codec:"c,omitempty,allocbound=8"`
	D string    `codec:"d,omitempty"`
	E [2]string `codec:"e,omitempty,omitemptyarray"`

	// This triggers some other bugs in msgp...
	// F struct {
	// 	_struct struct{} `codec:",omitempty,omitemptyarray"`
	// } `codec:"f,omitempty"`

	//msgp:sort SortableUint64 SortUint64
	G map[SortableUint64]uint64 `codec:"g,omitempty,allocbound=4"`
	H int64             `codec:"h,omitempty"`
	I int64             `codec:"i,omitempty"`
}

type SortableUint64 uint64

//msgp:ignore SortUint64
//msgp:sort SortableUint64 SortUint64
type SortUint64 []SortableUint64

func (a SortUint64) Len() int           { return len(a) }
func (a SortUint64) Less(i, j int) bool { return a[i] < a[j] }
func (a SortUint64) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
