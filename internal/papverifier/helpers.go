package papverifier

import (
	"regexp"
	"time"
)

var regexCache2 = map[string]*regexp.Regexp{}

func regexpCompile(pat string) *regexp.Regexp {
	if re, ok := regexCache2[pat]; ok {
		return re
	}
	re, _ := regexp.Compile(pat)
	regexCache2[pat] = re
	return re
}

func matchPattern(s, pat string) bool {
	return regexpCompile(pat).MatchString(s)
}

func validRFC3339(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	if err != nil {
		_, err = time.Parse(time.RFC3339Nano, s)
	}
	return err == nil
}
