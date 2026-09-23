package util

import (
	"context"
	"errors"
	"testing"
)

func TestResolveDomainContextLiterals(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{" https://192.0.2.1:51820/ ", "192.0.2.1:51820"},
		{"http://[2001:db8::1]:51820/", "[2001:db8::1]:51820"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		got, err := ResolveDomainContext(context.Background(), tc.input)
		if err != nil || got != tc.want {
			t.Errorf("ResolveDomainContext(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}

func TestResolveDomainContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, endpoint := range []string{"blocked.invalid:51820", "192.0.2.1:51820"} {
		if _, err := ResolveDomainContext(ctx, endpoint); !errors.Is(err, context.Canceled) {
			t.Errorf("ResolveDomainContext(%q) = %v; want canceled", endpoint, err)
		}
	}
}
