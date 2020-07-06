package mtls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInAllowedCNs(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		allowed  []string
		expected bool
	}{
		{
			name:     "wildcard match",
			cn:       "foo.mauve.de",
			allowed:  []string{"*.mauve.de"},
			expected: true,
		},
		{
			name:     "perfect match",
			cn:       "foo.mauve.de",
			allowed:  []string{"foo.mauve.de"},
			expected: true,
		},
		{
			name:     "no match",
			cn:       "foo.mauve.de",
			allowed:  []string{"*.as48821.net"},
			expected: false,
		},
		{
			name:     "nothing allowed",
			cn:       "foo.mauve.de",
			allowed:  []string{},
			expected: false,
		},
		{
			name:     "all",
			cn:       "foo.bar",
			allowed:  []string{"*"},
			expected: true,
		},
		{
			name:     "any",
			cn:       "foo.bar",
			allowed:  []string{"test", "*"},
			expected: true,
		},
	}

	t.Parallel()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isInAllowedCNs(test.cn, test.allowed))
		})
	}
}
