package ciphers

import (
	"math"
)

type Set[T comparable] interface {
	add(t T)
	remove(t T)
	check(t T) bool
	len() int
	keys() []T
}

type GSet[T comparable] struct {
	setimp map[T]bool
}

func NewGSet[T comparable]() GSet[T] {
	gset := new(GSet[T])
	gset.setimp = make(map[T]bool)
	return *gset
}

func (g *GSet[T]) add(t T) {
	g.setimp[t] = true
}
func (g *GSet[T]) remove(t T) {
	delete(g.setimp, t)
}
func (g *GSet[T]) check(t T) bool {
	_, exists := g.setimp[t]
	return exists
}
func (g *GSet[T]) len() int {
	return len(g.setimp)
}
func (g *GSet[T]) keys() []T {
	var res []T = make([]T, 0, len(g.setimp))
	for key, _ := range g.setimp {
		res = append(res, key)
	}

	return res
}


type SignedInteger interface {
	int | int8 | int16 | int32 | int64
}
type UnsignedInteger interface {
	uint | uint8 | uint16 | uint32 | uint64
}
type Integer interface {
	SignedInteger | UnsignedInteger
}

type Float interface {
	float32 | float64
}

type Number interface {
	Integer | Float
}

// Get the raw distance from the expected value
func absoluteError[T Number](observedv, truev T) float64 {
	return math.Abs(float64(observedv - truev))
}
// Get the relative distance from the expected value
func relativeError[T Number](observedv, truev T) float64 {
	return absoluteError(observedv, truev) / float64(truev)
}
// Get the percentage distance from the expected value
func percentageError[T Number](observedv, truev T) float64 {
	return relativeError(observedv, truev) * 100
}