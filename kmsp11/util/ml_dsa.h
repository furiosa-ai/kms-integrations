/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_UTIL_ML_DSA_H_
#define KMSP11_UTIL_ML_DSA_H_

#include <memory>
#include <string>
#include <string_view>

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "common/kms_v1.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

// Sizes (in bytes) of the FIPS 204 encodings for an ML-DSA parameter set.
struct MlDsaSizes {
  size_t public_key_bytes;
  size_t signature_bytes;
};

// An ML-DSA public key in the FIPS 204 encoding, tagged with its parameter set.
struct MlDsaPublicKey {
  CK_ML_DSA_PARAMETER_SET_TYPE parameter_set;
  std::string value;
};

// Returns the encoding sizes for the provided parameter set.
absl::StatusOr<MlDsaSizes> GetMlDsaSizes(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set);

// The size (in bytes) of the FIPS 204 message representative mu.
inline constexpr size_t kMlDsaMuBytes = 64;

// Returns the ML-DSA parameter set for a Cloud KMS algorithm, or an error if
// the algorithm is not an ML-DSA algorithm. Both the PQ_SIGN_ML_DSA_* and the
// PQ_SIGN_ML_DSA_*_EXTERNAL_MU algorithms are ML-DSA algorithms.
absl::StatusOr<CK_ML_DSA_PARAMETER_SET_TYPE> MlDsaParameterSetForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns true if the provided algorithm is an ML-DSA algorithm.
bool IsMlDsaAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns true if the provided algorithm is a PQ_SIGN_ML_DSA_*_EXTERNAL_MU
// algorithm, for which Cloud KMS signs a caller-computed message representative
// mu (FIPS 204, Algorithm 7, line 6) rather than the message itself.
bool IsMlDsaExternalMuAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Wraps a FIPS 204 encoded public key in a DER-encoded X.509
// SubjectPublicKeyInfo, using the algorithm identifiers from RFC 9881.
absl::StatusOr<std::string> MarshalMlDsaPublicKeyDer(
    CK_ML_DSA_PARAMETER_SET_TYPE parameter_set, std::string_view public_key);

// Parses a DER-encoded X.509 SubjectPublicKeyInfo containing an ML-DSA key.
absl::StatusOr<MlDsaPublicKey> ParseMlDsaPublicKeyDer(
    std::string_view public_key_der);

// Returns true if the crypto library that this binary was built with is able
// to verify ML-DSA signatures.
bool MlDsaVerificationSupported();

// Returns true if the crypto library that this binary was built with is able
// to compute the ML-DSA message representative mu.
bool MlDsaExternalMuSupported();

// Incrementally computes the FIPS 204 message representative
//   mu = SHAKE256(tr || IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) ||
//                 ctx || M, 64), where tr = SHAKE256(pk, 64),
// which is the value that ML-DSA.Sign (FIPS 204, Algorithm 2) signs for
// message M and context string ctx.
class MlDsaMuBuilder {
 public:
  // Returns a builder for the provided public key and context string, which
  // may not exceed 255 bytes. Fails with CKR_MECHANISM_INVALID if the crypto
  // library cannot compute mu.
  static absl::StatusOr<std::unique_ptr<MlDsaMuBuilder>> New(
      const MlDsaPublicKey& public_key, absl::Span<const uint8_t> context);

  virtual ~MlDsaMuBuilder() = default;

  // Appends a part of the message.
  virtual void Update(absl::Span<const uint8_t> data) = 0;

  // Returns mu. Must be called at most once.
  virtual std::string Finalize() = 0;
};

// Verifies an ML-DSA signature over `data` with the provided context string.
// Returns CKR_SIGNATURE_INVALID if the signature does not verify.
absl::Status MlDsaVerify(const MlDsaPublicKey& public_key,
                         absl::Span<const uint8_t> data,
                         absl::Span<const uint8_t> context,
                         absl::Span<const uint8_t> signature);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_ML_DSA_H_
