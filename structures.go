package ciphers

type Set[T comparable] interface {
	add(t T)
	remove(t T)
	check(t T) bool
	len() int
}

type GSet[T comparable] struct {
	setimp map[T]bool
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

/* Man, go syntax is annoying. It took me ages to figure out the difference between 
`func (g *GSet) <funcname>` and `func (g *GSet[T]) <funcname>`. Thanks to blackgreen on
stackoverflow: https://stackoverflow.com/a/72050933 */