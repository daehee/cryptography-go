package utils

import (
	"sort"
	"unicode"
)

type FreqMap map[rune]int

type FreqKV struct {
	Ch    rune
	Count int
}

type FreqKVList []FreqKV

func (f FreqKVList) Len() int           { return len(f) }
func (f FreqKVList) Less(i, j int) bool { return f[i].Count < f[j].Count }
func (f FreqKVList) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }

func sortByCount(m FreqMap) FreqKVList {
	fl := make(FreqKVList, len(m))
	i := 0
	for k, v := range m {
		fl[i] = FreqKV{k, v}
		i++
	}
	sort.Sort(sort.Reverse(fl))
	return fl
}

func scoreFrequency(f FreqKVList) int {
	// fChars := []rune{'E', 'T', 'A', 'O', 'I', 'N'}
	fChars := []rune{'E', 'T', 'A', 'O', 'I', 'N', ' ', 'S', 'H', 'R', 'D', 'L', 'U'}
	// fLeast := []rune{'V', 'K', 'J', 'X', 'Q', 'Z'}
	var score int

	// Does top 6 contain ETAOIN SHRDLU?
	var bound_min int
	if len(f) < len(fChars) {
		bound_min = len(f)
	} else {
		bound_min = len(fChars)
	}
	for _, v := range f[0:bound_min] {
		for i, c := range fChars {
			if unicode.ToUpper(rune(v.Ch)) == c {
				weighted := len(fChars) - i
				score += weighted * v.Count
				// fmt.Printf("score: %d (weighted) X %d -- %s\n", weighted, v.Count, string(c))
			}
		}
	}

	return score
}

func Frequency(s string) int {
	m := FreqMap{}
	for _, r := range s {
		// Only count if between A-Z or a-z or space
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r == ' ') {
			m[r]++
		}
	}
	// Sort by frequency count DESC
	mSorted := sortByCount(m)
	// Score by ETAOIN SHRDLU
	score := scoreFrequency(mSorted)

	return score
}
