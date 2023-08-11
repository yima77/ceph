#pragma once

#include <map>
#include <string>
#include <tuple>

#include "common/dout.h"
#include "include/common_fwd.h"
#include "common/async/yield_context.h"

namespace rgw {
namespace secret {

class RGWSecretEncrypter
{
public:
  virtual ~RGWSecretEncrypter() {}

  // Encrypt a secret. Return a tuple of:
  // 1, Key ID, which indicates which key is used to encrypt the secret. 0 means not encrypted, either the feature is not enabled or no encryption key available.
  // 2, Encrypted secret.
  virtual std::tuple<uint32_t, std::string> encrypt(const std::string& secret) = 0;

  // Decrypt a secret. Return a tuple of:
  // 1, Decryption happened and was successful.
  // 2, Key ID, which is the id of the key that SHOULD be used to encrypt the secret. If it is different from key_id, it means
  //    key needs rotation or encryption feature is disabled (Key ID == 0).
  // 3, Decrypted secret.
  virtual std::tuple<bool, uint32_t, std::string> decrypt(uint32_t key_id, const std::string& secret) = 0;
};

int init_encrypter(CephContext *const cct, bool enabled, const std::string &encrypt_key_file);

RGWSecretEncrypter *encrypter();

}
}
