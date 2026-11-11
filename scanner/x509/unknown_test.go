// Copyright 2026 PQCA
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func syntheticCertificate(t *testing.T, unknownSignature, unknownKey bool) *stdx509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: stdx509.ECDSAWithSHA256}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var outer certificateOuterASN1
	if _, err = asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	if _, err = asn1.Unmarshal(outer.TBSCertificate.FullBytes, &fields); err != nil {
		t.Fatal(err)
	}
	if unknownSignature {
		outer.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}}
		fields[2].FullBytes, err = asn1.Marshal(outer.SignatureAlgorithm)
		if err != nil {
			t.Fatal(err)
		}
	}
	if unknownKey {
		var spki subjectPublicKeyInfoASN1
		if _, err = asn1.Unmarshal(fields[6].FullBytes, &spki); err != nil {
			t.Fatal(err)
		}
		spki.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}}
		fields[6].FullBytes, err = asn1.Marshal(spki)
		if err != nil {
			t.Fatal(err)
		}
	}
	var content []byte
	for _, field := range fields {
		content = append(content, field.FullBytes...)
	}
	outer.TBSCertificate = asn1.RawValue{Tag: 16, IsCompound: true, Bytes: content}
	der, err = asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	// This exercise verifies parsing/inventory, never the modified signature.
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestUnknownAlgorithmsKeepCertificateAndRawOIDs(t *testing.T) {
	for _, pair := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprint(pair), func(t *testing.T) {
			cert := syntheticCertificate(t, pair[0], pair[1])
			withMeta, err := NewX509CertificateWithMetadata(cert, "fixture.der")
			if err != nil {
				t.Fatal(err)
			}
			components, _, err := GenerateCdxComponents(withMeta)
			if err != nil {
				t.Fatal(err)
			}
			refs := map[string]cdx.Component{}
			var certificate cdx.Component
			for _, c := range *components {
				refs[c.BOMRef] = c
				if c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
					certificate = c
				}
			}
			if certificate.BOMRef == "" {
				t.Fatal("certificate dropped")
			}
			if certificate.Hashes == nil || (*certificate.Hashes)[0].Value != fmt.Sprintf("%x", sha256.Sum256(cert.Raw)) {
				t.Fatal("certificate fingerprint lost")
			}
			props := certificate.CryptoProperties.CertificateProperties
			sig := refs[string(props.SignatureAlgorithmRef)]
			publicKey := refs[string(props.SubjectPublicKeyRef)]
			pub := refs[string(publicKey.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef)]
			for i, c := range []cdx.Component{sig, pub} {
				if pair[i] {
					want := fmt.Sprintf("1.3.6.1.4.1.55555.%d", i+1)
					if c.CryptoProperties.OID != want || !strings.HasPrefix(c.Name, "Unknown algorithm") {
						t.Fatalf("raw OID/unknown status lost: %+v", c)
					}
					if c.CryptoProperties.AlgorithmProperties.Primitive != cdx.CryptoPrimitiveOther {
						t.Fatal("invented algorithm support")
					}
				} else if strings.HasPrefix(c.Name, "Unknown") {
					t.Fatal("known algorithm regressed")
				}
			}
			for _, c := range []cdx.Component{certificate, sig, publicKey, pub} {
				if c.Evidence == nil || c.Evidence.Occurrences == nil || (*c.Evidence.Occurrences)[0].Location != "fixture.der" {
					t.Fatal("location lost")
				}
			}
		})
	}
}

func TestMalformedRawOIDDoesNotInventCertificateAlgorithms(t *testing.T) {
	cert := syntheticCertificate(t, true, true)
	if _, ok := rawSignatureAlgorithmOID(append(cert.Raw, 0)); ok {
		t.Fatal("trailing bytes accepted")
	}
	if _, _, ok := rawPublicKeyInfo(append(cert.RawSubjectPublicKeyInfo, 0)); ok {
		t.Fatal("trailing SPKI accepted")
	}
	cert.RawSubjectPublicKeyInfo = []byte{0x30, 0x01}
	withMeta, _ := NewX509CertificateWithMetadata(cert, "bad.der")
	if _, _, err := GenerateCdxComponents(withMeta); err == nil {
		t.Fatal("malformed raw key accepted")
	}
}
