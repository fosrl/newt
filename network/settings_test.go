package network

import "testing"

func TestAddIPv4AddressRequiresPrimary(t *testing.T) {
	ClearNetworkSettings()
	defer ClearNetworkSettings()

	if err := AddIPv4Address("10.10.0.5", "255.255.255.255"); err == nil {
		t.Fatal("expected an error adding a secondary address before any primary address is set")
	}
	if got := GetSettings().IPv4Addresses; len(got) != 0 {
		t.Errorf("IPv4Addresses = %v, want empty after a rejected add", got)
	}
}

func TestAddIPv4AddressAfterPrimarySucceeds(t *testing.T) {
	ClearNetworkSettings()
	defer ClearNetworkSettings()

	SetIPv4Settings([]string{"10.10.0.1"}, []string{"255.255.255.0"})

	if err := AddIPv4Address("10.10.0.5", "255.255.255.255"); err != nil {
		t.Fatalf("unexpected error adding secondary address: %v", err)
	}

	got := GetSettings().IPv4Addresses
	want := []string{"10.10.0.1", "10.10.0.5"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("IPv4Addresses = %v, want %v", got, want)
	}
}
