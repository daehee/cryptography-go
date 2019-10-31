package luhn

import (
	"regexp"
	"strconv"
	"strings"
)

func Valid(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 2 || hasIllegalChars(s) {
		return false
	}
	return luhnChecksum(s) == 0
}

func hasIllegalChars(s string) bool {
	nondigitRegexp := regexp.MustCompile(`[^0-9]`)
	if strings.ContainsAny(s, "-#$") || nondigitRegexp.MatchString(s) {
		return true
	}
	return false
}

func luhnChecksum(cardNumber string) int {
	digits := digitsOf(cardNumber)
	odd, even := splitOddEven(digits)
	total := sum(odd)
	for _, d := range even {
		total += sum(digitsOf(strconv.Itoa(d * 2)))
	}
	return total % 10
}

func digitsOf(cardNumber string) []int {
	digits := make([]int, 0)
	for _, r := range cardNumber {
		digits = append(digits, int(r - '0'))
	}
	return digits
}

func splitOddEven(digits []int) ([]int, []int) {
    digits = reverse(digits)
	var odd, even []int
	for i := len(digits)-1; i >= 0; i-- {
		if i % 2 != 0 {
			even = append(even, digits[i])
		} else {
			odd = append(odd, digits[i])
		}
	}
	return odd, even
}

func sum(digits []int) int {
	sum := 0
	for _, d := range digits {
		sum += d
	}
	return sum
}

func reverse(a []int) []int {
	for i := len(a)/2-1; i >= 0; i-- {
		opp := len(a)-1-i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}
