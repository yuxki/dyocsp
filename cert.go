package dyocsp

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

const (
	constructedBit      = 0x20
	constructedSequence = asn1.TagSequence | constructedBit
	iniZeroOfBitString  = 0x00
	longFormCheckMask   = 0x80

	tagLen       = 1
	shortFormLen = 1
)

func skipIDAndLenOctets(octets []byte, offset int) int {
	offset += tagLen // Identifier octet
	if octets[offset]&longFormCheckMask > 0 {
		lenLen := ((octets[offset] << 1) >> 1)
		offset++
		offset += int(lenLen) // length octet
	} else {
		offset += shortFormLen // length octet
	}

	return offset
}

func skipIDAndLenAndContOctets(octets []byte, offset int) int {
	offset += tagLen // Identifier octet - 1byte
	if octets[offset]&longFormCheckMask > 0 {
		lenLen := ((octets[offset] << 1) >> 1)
		offset++
		conLen := int(binary.BigEndian.Uint64(octets[offset:lenLen]))
		offset += int(lenLen) // length octet
		offset += conLen      // content octet
	} else {
		offset += shortFormLen          // length octet
		offset += int(octets[offset-1]) // content octet
	}

	return offset
}

func extractSubjectPublicKey(keyInfo []byte) ([]byte, error) {
	var offset int

	// Constructed SEQUENCE
	if keyInfo[offset] != constructedSequence {
		return nil, invalidPKIResourceError{
			responderCert, fmt.Sprintf("offset %d is not ASN.1 Constructed SEQUENCE.", offset),
		}
	}

	// subectPublicKeyInfo identifier and length octets
	offset = skipIDAndLenOctets(keyInfo, offset)

	// Constructed SEQUENCE
	if keyInfo[offset] != constructedSequence {
		return nil, invalidPKIResourceError{
			responderCert, fmt.Sprintf("offset %d is not ASN.1 Constructed SEQUENCE.", offset),
		}
	}

	// subectPublicKeyInfo identifier and length and content octets
	offset = skipIDAndLenAndContOctets(keyInfo, offset)

	// Primitive BIT STRING
	if keyInfo[offset] != asn1.TagBitString {
		return nil, invalidPKIResourceError{
			responderCert, fmt.Sprintf("offset %d is not ASN.1 BIT STRING.", offset),
		}
	}

	// subectPublicKey  identifier and length octets
	offset = skipIDAndLenOctets(keyInfo, offset)

	// initial octet followed by zero of BIT STRING content
	if keyInfo[offset] != iniZeroOfBitString {
		return nil, invalidPKIResourceError{
			responderCert, fmt.Sprintf(
				"offset %d is not ASN.1 initial octet followed by zero of BIT STRING content.",
				offset,
			),
		}
	}
	offset++

	return keyInfo[offset:], nil
}
