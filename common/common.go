// Package common contains common utilities that are shared among other packages.
package common

import (
	"fmt"
	"regexp"
	"regexp/syntax"
)

const maxRegexLen = 10000

// SafeCompileRegex compiles a regex pattern with safety checks against
// catastrophic backtracking (ReDoS). It validates the parsed syntax tree
// depth and rejects overly long patterns.
func SafeCompileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (%d > %d)", len(pattern), maxRegexLen)
	}
	// Parse the syntax tree to check complexity.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	if depth := maxDepth(re, 0); depth > 20 {
		return nil, fmt.Errorf("regex nesting depth %d exceeds limit", depth)
	}
	return regexp.Compile(pattern)
}

func maxDepth(re *syntax.Regexp, cur int) int {
	best := cur
	for _, sub := range re.Sub {
		if d := maxDepth(sub, cur+1); d > best {
			best = d
		}
	}
	return best
}
