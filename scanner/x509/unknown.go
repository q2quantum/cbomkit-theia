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
	"encoding/asn1"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// getUnknownAlgorithmComponent preserves an unrecognized AlgorithmIdentifier.
// The OID is observed data, not a claim of algorithm support, security level,
// signature verification, or certificate trust.
func getUnknownAlgorithmComponent(path string, oid asn1.ObjectIdentifier) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   "Unknown algorithm (OID " + oid.String() + ")",
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			OID:                 oid.String(),
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveOther},
		},
		Properties: &[]cdx.Property{{Name: "theia:algorithm:recognition", Value: "unknown"}},
		Evidence:   &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path}}},
	}
}
