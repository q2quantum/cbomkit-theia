// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// ML-DSA (FIPS 204) is not recognized by Go's crypto/x509 as of the Go
// version pinned in go.mod (1.26.8): x509.ParseCertificate succeeds without
// error on an ML-DSA certificate, but cert.SignatureAlgorithm and
// cert.PublicKeyAlgorithm both come back as their Unknown* zero value --
// the standard library has no named constant for these OIDs to match in a
// switch. Confirmed live (quantum-map pqc_mig_inv_exam, 2026-10-19): an
// ML-DSA-65 certificate parses with no error, SignatureAlgorithm == 0.
//
// Registered under NIST's digital-signature-algorithm arc
// (2.16.840.1.101.3.4.3.*) -- the same arc as id-dsa-with-sha256 (…3.2),
// already handled by the switch above. Source: NIST CSOR / FIPS 204 Appendix,
// mirrored in draft-ietf-lamps-dilithium-certificates.
var (
	oidSignatureMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidSignatureMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidSignatureMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// mlDSAVariant maps a recognized ML-DSA OID to its component name and FIPS
// 204 parameter-set identifier. ok is false for any other OID.
func mlDSAVariant(oid asn1.ObjectIdentifier) (name string, paramSet string, ok bool) {
	switch {
	case oid.Equal(oidSignatureMLDSA44):
		return "ML-DSA-44", "44", true
	case oid.Equal(oidSignatureMLDSA65):
		return "ML-DSA-65", "65", true
	case oid.Equal(oidSignatureMLDSA87):
		return "ML-DSA-87", "87", true
	default:
		return "", "", false
	}
}

// certificateOuterASN1 is a minimal mirror of the outer Certificate ASN.1
// SEQUENCE (RFC 5280 §4.1 -- tbsCertificate, signatureAlgorithm,
// signatureValue). Used only to recover the signatureAlgorithm
// AlgorithmIdentifier's OID directly from the DER when Go's typed
// x509.SignatureAlgorithm enum does not recognize it.
type certificateOuterASN1 struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// subjectPublicKeyInfoASN1 mirrors SubjectPublicKeyInfo (RFC 5280 §4.1 --
// algorithm, subjectPublicKey). Used to recover the public-key
// AlgorithmIdentifier's OID, and the raw key bytes, directly from the DER
// when Go's typed x509.PublicKeyAlgorithm enum does not recognize it.
type subjectPublicKeyInfoASN1 struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// rawSignatureAlgorithmOID extracts the certificate's signatureAlgorithm OID
// directly from the outer Certificate DER (cert.Raw), bypassing Go's typed
// SignatureAlgorithm enum. ok is false only if the bytes don't parse at this
// level, which should not happen for a certificate that x509.ParseCertificate
// already accepted.
func rawSignatureAlgorithmOID(certDER []byte) (oid asn1.ObjectIdentifier, ok bool) {
	var outer certificateOuterASN1
	if _, err := asn1.Unmarshal(certDER, &outer); err != nil {
		return nil, false
	}
	return outer.SignatureAlgorithm.Algorithm, true
}

// rawPublicKeyInfo extracts the subjectPublicKeyInfo algorithm OID and raw
// key bytes directly from cert.RawSubjectPublicKeyInfo, bypassing Go's typed
// PublicKeyAlgorithm enum and PublicKey field (both unset for an algorithm Go
// does not recognize).
func rawPublicKeyInfo(rawSPKI []byte) (oid asn1.ObjectIdentifier, keyBytes []byte, ok bool) {
	var spki subjectPublicKeyInfoASN1
	if _, err := asn1.Unmarshal(rawSPKI, &spki); err != nil {
		return nil, nil, false
	}
	return spki.Algorithm.Algorithm, spki.PublicKey.Bytes, true
}

// getMLDSAAlgorithmComponent builds the composite signature/public-key
// algorithm component for an ML-DSA certificate. Like Ed25519
// (getEd25519AlgorithmComponent above, reused for both
// getSignatureAlgorithmComponent and getPublicKeyAlgorithmComponent), ML-DSA
// has no separate hash step at the certificate AlgorithmIdentifier level --
// the algorithm name *is* the composite hashAndSignature algorithm.
func getMLDSAAlgorithmComponent(path, name, paramSet string, oid asn1.ObjectIdentifier) cdx.Component {
	comp := getGenericSignatureAlgorithmComponent(path)
	comp.Name = name
	comp.CryptoProperties.OID = oid.String()
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = paramSet
	return comp
}

// getMLDSAPublicKeyComponent builds the related-crypto-material component
// for an ML-DSA certificate's public key. cert.PublicKey is nil for an
// algorithm Go's crypto/x509 does not recognize, so this reads the raw key
// bytes out of SubjectPublicKeyInfo directly instead of going through
// scanner/key's typed-key switch (mirrors getRSAPublicKeyComponent etc. in
// scanner/key/key.go: Value holds the PKIX-wrapped (SubjectPublicKeyInfo DER)
// form, base64-encoded; Size is the raw key length in bits, not the DER
// wrapper length).
func getMLDSAPublicKeyComponent(path, name string, rawSPKI, keyBytes []byte) cdx.Component {
	size := len(keyBytes) * 8
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:  cdx.RelatedCryptoMaterialTypePublicKey,
				Size:  &size,
				Value: base64.StdEncoding.EncodeToString(rawSPKI),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: path},
			},
		},
	}
}
