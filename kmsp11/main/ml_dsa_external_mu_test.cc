// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// End-to-end tests of ML-DSA signing with a context string, through the
// PKCS #11 function list, against the ML-DSA fake of Cloud KMS.

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_format.h"
#include "common/openssl.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/common_setup.h"
#include "kmsp11/test/ml_dsa_fake_kms.h"

#if defined(OPENSSL_IS_BORINGSSL) && defined(__has_include)
#if __has_include("openssl/mldsa.h")
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"
#define KMSP11_HAVE_MLDSA 1
#endif
#endif

namespace cloud_kms::kmsp11 {
namespace {

#ifdef KMSP11_HAVE_MLDSA

constexpr std::string_view kKeyRing =
    "projects/foo/locations/global/keyRings/bar";

// The context string of the composite signature scheme
// MLDSA87-RSA3072-PSS-SHA512 (draft-ietf-lamps-pq-composite-sigs).
constexpr char kLabel[] = "COMPSIG-MLDSA87-RSA3072-PSS-SHA512";

class MlDsaExternalMuBridgeTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_, MlDsaFakeKms::New());
    ASSERT_OK(fake_->CreateKey(
        kKeyRing, "mu87",
        kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87_EXTERNAL_MU));
    ASSERT_OK(fake_->CreateKey(kKeyRing, "plain87",
                               kms_v1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87));

    config_file_ = std::tmpnam(nullptr);
    std::ofstream(config_file_) << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                                                   kKeyRing,
                                                   fake_->listen_addr());

    ASSERT_OK(GetFunctionList(&f_));
    CK_C_INITIALIZE_ARGS init_args = InitArgs(config_file_.c_str());
    ASSERT_EQ(f_->C_Initialize(&init_args), CKR_OK);
    initialized_ = true;
    ASSERT_EQ(f_->C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr,
                                &session_),
              CKR_OK);
  }

  void TearDown() override {
    if (initialized_) {
      EXPECT_EQ(f_->C_Finalize(nullptr), CKR_OK);
    }
    if (!config_file_.empty()) {
      std::remove(config_file_.c_str());
    }
  }

  CK_OBJECT_HANDLE FindKey(CK_OBJECT_CLASS object_class, std::string label) {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &object_class, sizeof(object_class)},
        {CKA_LABEL, label.data(), label.size()},
    };
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    EXPECT_EQ(f_->C_FindObjectsInit(session_, tmpl, 2), CKR_OK);
    EXPECT_EQ(f_->C_FindObjects(session_, &handle, 1, &count), CKR_OK);
    EXPECT_EQ(f_->C_FindObjectsFinal(session_), CKR_OK);
    EXPECT_EQ(count, 1);
    return handle;
  }

  std::unique_ptr<MlDsaFakeKms> fake_;
  std::string config_file_;
  CK_FUNCTION_LIST* f_ = nullptr;
  bool initialized_ = false;
  CK_SESSION_HANDLE session_ = CK_INVALID_HANDLE;
};

TEST_F(MlDsaExternalMuBridgeTest, SignWithContextVerifiesWithStandardMlDsa87) {
  CK_OBJECT_HANDLE prv = FindKey(CKO_PRIVATE_KEY, "mu87");
  CK_OBJECT_HANDLE pub = FindKey(CKO_PUBLIC_KEY, "mu87");

  // The key type and the backing Cloud KMS algorithm are discoverable.
  CK_KEY_TYPE key_type;
  CK_ULONG parameter_set, kms_algorithm;
  CK_ATTRIBUTE attrs[] = {
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_PARAMETER_SET, &parameter_set, sizeof(parameter_set)},
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
  };
  ASSERT_EQ(f_->C_GetAttributeValue(session_, prv, attrs, 3), CKR_OK);
  EXPECT_EQ(key_type, CKK_ML_DSA);
  EXPECT_EQ(parameter_set, CKP_ML_DSA_87);
  EXPECT_EQ(kms_algorithm, KMS_ALGORITHM_PQ_SIGN_ML_DSA_87_EXTERNAL_MU);

  // A 131-byte message.
  std::vector<CK_BYTE> msg(131);
  for (size_t i = 0; i < msg.size(); i++) {
    msg[i] = static_cast<CK_BYTE>(i);
  }

  CK_SIGN_ADDITIONAL_CONTEXT params = {
      CKH_HEDGE_PREFERRED, reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(kLabel)),
      sizeof(kLabel) - 1};
  CK_MECHANISM mech = {CKM_ML_DSA, &params, sizeof(params)};
  ASSERT_EQ(f_->C_SignInit(session_, &mech, prv), CKR_OK);

  CK_ULONG sig_len = 0;
  ASSERT_EQ(f_->C_Sign(session_, msg.data(), msg.size(), nullptr, &sig_len),
            CKR_OK);
  ASSERT_EQ(sig_len, MLDSA87_SIGNATURE_BYTES);
  std::vector<CK_BYTE> sig(sig_len);
  ASSERT_EQ(f_->C_Sign(session_, msg.data(), msg.size(), sig.data(), &sig_len),
            CKR_OK);
  EXPECT_EQ(fake_->external_mu_sign_count(), 1);

  // Verify with BoringSSL's standard ML-DSA-87 Verify, using the FIPS 204
  // public key from CKA_VALUE.
  std::vector<CK_BYTE> pk(MLDSA87_PUBLIC_KEY_BYTES);
  CK_ATTRIBUTE value = {CKA_VALUE, pk.data(), pk.size()};
  ASSERT_EQ(f_->C_GetAttributeValue(session_, pub, &value, 1), CKR_OK);
  ASSERT_EQ(value.ulValueLen, MLDSA87_PUBLIC_KEY_BYTES);
  auto public_key = std::make_unique<MLDSA87_public_key>();
  CBS cbs;
  CBS_init(&cbs, pk.data(), pk.size());
  ASSERT_EQ(MLDSA87_parse_public_key(public_key.get(), &cbs), 1);

  EXPECT_EQ(MLDSA87_verify(public_key.get(), sig.data(), sig.size(),
                           msg.data(), msg.size(),
                           reinterpret_cast<const uint8_t*>(kLabel),
                           sizeof(kLabel) - 1),
            1);
  EXPECT_EQ(MLDSA87_verify(public_key.get(), sig.data(), sig.size(),
                           msg.data(), msg.size(), nullptr, 0),
            0);

  // C_Verify with the same context also accepts it.
  ASSERT_EQ(f_->C_VerifyInit(session_, &mech, pub), CKR_OK);
  EXPECT_EQ(f_->C_Verify(session_, msg.data(), msg.size(), sig.data(),
                         sig.size()),
            CKR_OK);
}

TEST_F(MlDsaExternalMuBridgeTest, MultiPartSignWithContext) {
  CK_OBJECT_HANDLE prv = FindKey(CKO_PRIVATE_KEY, "mu87");
  CK_OBJECT_HANDLE pub = FindKey(CKO_PUBLIC_KEY, "mu87");

  CK_SIGN_ADDITIONAL_CONTEXT params = {
      CKH_HEDGE_REQUIRED, reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(kLabel)),
      sizeof(kLabel) - 1};
  CK_MECHANISM mech = {CKM_ML_DSA, &params, sizeof(params)};

  // Larger than the 64 KiB limit that applies to PQ_SIGN_ML_DSA_* keys.
  std::vector<CK_BYTE> msg(200 * 1024, 'm');
  ASSERT_EQ(f_->C_SignInit(session_, &mech, prv), CKR_OK);
  ASSERT_EQ(f_->C_SignUpdate(session_, msg.data(), 100 * 1024), CKR_OK);
  ASSERT_EQ(f_->C_SignUpdate(session_, msg.data() + 100 * 1024,
                             msg.size() - 100 * 1024),
            CKR_OK);
  std::vector<CK_BYTE> sig(MLDSA87_SIGNATURE_BYTES);
  CK_ULONG sig_len = sig.size();
  ASSERT_EQ(f_->C_SignFinal(session_, sig.data(), &sig_len), CKR_OK);

  ASSERT_EQ(f_->C_VerifyInit(session_, &mech, pub), CKR_OK);
  EXPECT_EQ(f_->C_Verify(session_, msg.data(), msg.size(), sig.data(),
                         sig_len),
            CKR_OK);
}

TEST_F(MlDsaExternalMuBridgeTest, ContextRejectedForPlainMlDsaKey) {
  CK_OBJECT_HANDLE prv = FindKey(CKO_PRIVATE_KEY, "plain87");

  CK_ULONG kms_algorithm;
  CK_ATTRIBUTE attr = {CKA_KMS_ALGORITHM, &kms_algorithm,
                       sizeof(kms_algorithm)};
  ASSERT_EQ(f_->C_GetAttributeValue(session_, prv, &attr, 1), CKR_OK);
  EXPECT_EQ(kms_algorithm, KMS_ALGORITHM_PQ_SIGN_ML_DSA_87);

  CK_SIGN_ADDITIONAL_CONTEXT params = {
      CKH_HEDGE_PREFERRED, reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(kLabel)),
      sizeof(kLabel) - 1};
  CK_MECHANISM mech = {CKM_ML_DSA, &params, sizeof(params)};
  EXPECT_EQ(f_->C_SignInit(session_, &mech, prv), CKR_MECHANISM_PARAM_INVALID);
  EXPECT_EQ(fake_->sign_count(), 0);
}

#endif  // KMSP11_HAVE_MLDSA

}  // namespace
}  // namespace cloud_kms::kmsp11
