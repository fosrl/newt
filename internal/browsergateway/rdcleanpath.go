package browsergateway

import (
	"encoding/asn1"
	"fmt"
)

// RDCleanPath PDU version (BASE_VERSION + 1 = 3389 + 1).
const rdCleanPathVersion = int64(3390)

// rdCleanPathPdu is a Go translation of the ASN.1 SEQUENCE defined in the
// ironrdp-rdcleanpath crate. All optional fields use EXPLICIT context-specific
// tagging, matching the Rust `der::Sequence` derivation with
// `tag_mode = "EXPLICIT"`.
//
// We only need a subset of fields for the basic proxy flow, but the struct
// declares every tag we may encounter so that decoding does not fail on an
// unexpected element.
type rdCleanPathPdu struct {
	Version           int64    `asn1:"explicit,tag:0"`
	Destination       string   `asn1:"explicit,tag:2,optional,utf8"`
	ProxyAuth         string   `asn1:"explicit,tag:3,optional,utf8"`
	ServerAuth        string   `asn1:"explicit,tag:4,optional,utf8"`
	PreconnectionBlob string   `asn1:"explicit,tag:5,optional,utf8"`
	X224              []byte   `asn1:"explicit,tag:6,optional"`
	ServerCertChain   [][]byte `asn1:"explicit,tag:7,optional"`
	ServerAddr        string   `asn1:"explicit,tag:9,optional,utf8"`
}

// decodeRDCleanPathRequest parses a client-to-proxy RDCleanPath PDU.
func decodeRDCleanPathRequest(buf []byte) (*rdCleanPathPdu, error) {
	var pdu rdCleanPathPdu
	rest, err := asn1.Unmarshal(buf, &pdu)
	if err != nil {
		return nil, fmt.Errorf("asn1 unmarshal: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after RDCleanPath PDU: %d bytes", len(rest))
	}
	if pdu.Version != rdCleanPathVersion {
		return nil, fmt.Errorf("unexpected RDCleanPath version: %d", pdu.Version)
	}
	return &pdu, nil
}

// encodeRDCleanPathResponse builds a proxy-to-client RDCleanPath response PDU
// containing the server address, X.224 connection confirm and server TLS chain.
func encodeRDCleanPathResponse(serverAddr string, x224Rsp []byte, certChain [][]byte) ([]byte, error) {
	pdu := rdCleanPathPdu{
		Version:         rdCleanPathVersion,
		X224:            x224Rsp,
		ServerCertChain: certChain,
		ServerAddr:      serverAddr,
	}
	return asn1.Marshal(pdu)
}

// detectRDCleanPathLength returns the total DER length of an RDCleanPath PDU
// if enough bytes are available, otherwise -1.
//
// The PDU is a DER SEQUENCE, which begins with the universal SEQUENCE tag
// (0x30) followed by a length octet/octets. We parse just enough to know the
// total length so we can buffer accordingly.
func detectRDCleanPathLength(buf []byte) int {
	if len(buf) < 2 {
		return -1
	}
	if buf[0] != 0x30 {
		// Not a SEQUENCE: cannot be RDCleanPath.
		return -2
	}
	l := buf[1]
	if l < 0x80 {
		return 2 + int(l)
	}
	n := int(l & 0x7f)
	if n == 0 || n > 4 {
		return -2
	}
	if len(buf) < 2+n {
		return -1
	}
	total := 0
	for i := 0; i < n; i++ {
		total = (total << 8) | int(buf[2+i])
	}
	return 2 + n + total
}
