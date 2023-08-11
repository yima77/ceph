#include <memory>
#include <map>
#include <vector>

#include "common/errno.h"
#include "common/dout.h"
#include "boost/container/flat_map.hpp"
#include "common/ceph_json.h"
#include "common/ceph_time.h"
#include "rgw_common.h"
#include "rgw_secret_encryption.h"
#include "auth/Crypto.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

namespace rgw { namespace secret {

struct RGWEncryptKey
{
  uint32_t id;
  std::string key;

  void decode_json(JSONObj *obj)
  {
    JSONDecoder::decode_json("id", id, obj);
    JSONDecoder::decode_json("key", key, obj);
  }
};

using RGWEncryptKeyMap = std::map<uint32_t, RGWEncryptKey>;

class RGWSecretEncrypterImpl : public RGWSecretEncrypter
{
public:
  RGWSecretEncrypterImpl(CephContext *const cct, bool enabled, const std::string &encrypt_key_file) : 
    cct(cct),
    enabled(enabled),
    encrypt_key_file(encrypt_key_file),
    curr_db(std::make_shared<RGWEncryptKeyMap>())
  {
    ldout(cct, 1)  << "Create secret encrypter with enablement " << enabled << dendl;
    reload_keys(0);
  }

protected:
  CephContext *const cct;

  bool enabled;

  const std::string encrypt_key_file;

  std::shared_ptr<RGWEncryptKeyMap> curr_db;

  int reload_keys(uint32_t expect_key_id);

  std::tuple<uint32_t, std::string> encrypt(const std::string& secret) override;

  std::tuple<bool, uint32_t, std::string> decrypt(uint32_t key_id, const std::string& secret) override;

};

static RGWSecretEncrypterImpl *TheSecretEncrypter = nullptr;

int init_encrypter(CephContext *const cct, bool enable, const std::string &encrypt_key_file)
{
  if (TheSecretEncrypter) {
    std::cerr << "ERROR: only one secret encrypter is allowed" << std::endl;
    return -EINVAL;
  }
  TheSecretEncrypter = new RGWSecretEncrypterImpl(cct, enable, encrypt_key_file);
  return 0;
}

RGWSecretEncrypter *encrypter()
{
  return TheSecretEncrypter;
}

// Stolen from rgw_admin.cc
static int read_input(CephContext *const cct, const std::string& infile, bufferlist& bl)
{
  int fd = 0;
  if (infile.size()) {
    fd = open(infile.c_str(), O_RDONLY);
    if (fd < 0) {
      int err = -errno;
      ldout(cct, 1)  << "error reading input file " << infile << " " << err << dendl;
      return err;
    }
  }

#define READ_CHUNK 8196
  int r;
  int err = 0;

  do {
    char buf[READ_CHUNK];

    r = safe_read(fd, buf, READ_CHUNK);
    if (r < 0) {
      err = -errno;
      ldout(cct, 1) << "error while reading input: " << err << dendl;
      goto out;
    }
    bl.append(buf, r);
  } while (r > 0);
  err = 0;

 out:
  if (infile.size()) {
    close(fd);
  }
  return err;
}

template <class T>
static int read_decode_json(CephContext *const cct, const std::string& infile, T& t)
{
  bufferlist bl;
  int ret = read_input(cct, infile, bl);
  if (ret < 0) {
    ldout(cct, 1) << "ERROR: failed to read input: " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  JSONParser p;
  if (!p.parse(bl.c_str(), bl.length())) {
    ldout(cct, 1) << "failed to parse JSON" << dendl;
    return -EINVAL;
  }

  try {
    decode_json_obj(t, &p);
  } catch (const JSONDecoder::err& e) {
    ldout(cct, 1) << "failed to decode JSON input: " << e.what() << dendl;
    return -EINVAL;
  }
  return 0;
}

int RGWSecretEncrypterImpl::reload_keys(uint32_t expect_key_id)
{
  ldout(cct, 1) << "Reload keys from " << encrypt_key_file << dendl;
  std::list<RGWEncryptKey> key_list;
  int r = read_decode_json(cct, encrypt_key_file, key_list);
  if (r < 0) {
    ldout(cct, 1) << "Failed to load secret encrypt keys" << dendl;
    return -EIO;
  }

  std::shared_ptr<RGWEncryptKeyMap> new_db = std::make_shared<RGWEncryptKeyMap>();
  for (const auto& key : key_list) {
    (*new_db)[key.id] = key;
  }
  if (!new_db->empty() and new_db->rbegin()->first >= expect_key_id) {
    curr_db.swap(new_db);
    return 0;
  } else {
    ldout(cct, 1) << "WARNING: key reloading doesn't cover key id " << expect_key_id << " with " << (new_db->empty() ? 0 : new_db->rbegin()->first) << dendl;
    return -EIO;
  }
}

std::tuple<bool, uint32_t, std::string> RGWSecretEncrypterImpl::decrypt(uint32_t key_id, const std::string& secret)
{
  ldout(cct, 1) << "INFO: attempt to decrypt secret: " << secret << " with key id " << key_id << dendl;
  auto db_in_use = curr_db; // Hold a reference of it
  if (key_id > 0 && !db_in_use->empty() && db_in_use->rbegin()->first < key_id) {
    // The secret was encrypted by a key that is newer than any in curr_db. Key file must be reloaded or we are going to DoS the client.
    reload_keys(key_id);
  }

  auto key_id_to_use = (enabled && !db_in_use->empty()) ? db_in_use->rbegin()->first : 0;
  auto key_found = db_in_use->find(key_id);
  if (key_found == db_in_use->end()) {
    if (key_id == 0) {
      return std::make_tuple(true, key_id_to_use, secret);
    } else {
      ldout(cct, 1) << "Unknow encrypt key ID [" << key_id << "] provided for encryption" << dendl;
      return std::make_tuple(false, 0, secret);
    }
  }

  const auto& key_str = key_found->second.key;
  ceph::bufferptr key_buf(key_str.data(), key_str.size());
  CryptoKey key_to_use{CEPH_CRYPTO_AES, ceph_clock_now(), key_buf};

  ldout(cct, 1) << "INFO: unique key to encrypt/decrypt: " << key_str << " for secret: " << secret << dendl;
  auto* cryptohandler = cct->get_crypto_handler(CEPH_CRYPTO_AES);

  if (cryptohandler->validate_secret(key_to_use.get_secret()) < 0) {
    ldout(cct, 1) << "ERROR: Invalid rgw secret encryption key, please ensure its length is 16" << dendl;
    return std::make_tuple(false, 0, secret);
  }

  std::string error;
  std::unique_ptr<CryptoKeyHandler> keyhandler(cryptohandler->get_key_handler(key_to_use.get_secret(), error));
  if (! keyhandler) {
    ldout(cct, 1) << "ERROR: No Key handler found: " << error << dendl;
    return std::make_tuple(false, 0, secret);
  }

  ceph::bufferlist in;
  ceph::bufferlist out;

  using ceph::encode;
  in.append(secret);

  ceph::bufferlist raw_in;
  raw_in.decode_base64(in);
  std::ostringstream to_show;
  raw_in.hexdump(to_show);
  ldout(cct, 1) << "INFO: decrypt input : " << to_show.str() << dendl;
  int ret = keyhandler->decrypt(raw_in, out, &error);
  if (ret < 0) {
    ldout(cct, 1) << "ERROR: fail to decrypt secret: " << ret << dendl;
    return std::make_tuple(false, 0, secret);
  }
  return std::make_tuple(true, key_id_to_use, out.to_str());
}

std::tuple<uint32_t, std::string> RGWSecretEncrypterImpl::encrypt(const std::string& secret)
{
  auto db_in_use = curr_db;
  if (db_in_use->empty() || !enabled) {
    return std::make_tuple(0, secret);
  }

  auto key_id_to_use = db_in_use->rbegin()->first;
  const auto& key_str = db_in_use->rbegin()->second.key;
  ceph::bufferptr key_buf(key_str.data(), key_str.size());
  CryptoKey key_to_use{CEPH_CRYPTO_AES, ceph_clock_now(), key_buf};

  ldout(cct, 1) << "INFO: unique key to encrypt/decrypt: " << key_str << " for secret: " << secret << dendl;
  auto* cryptohandler = cct->get_crypto_handler(CEPH_CRYPTO_AES);

  if (cryptohandler->validate_secret(key_to_use.get_secret()) < 0) {
    ldout(cct, 1) << "ERROR: Invalid rgw secret encryption key, please ensure its length is 16" << dendl;
    return std::make_tuple(0, secret);
  }

  std::string error;
  std::unique_ptr<CryptoKeyHandler> keyhandler(cryptohandler->get_key_handler(key_to_use.get_secret(), error));
  if (! keyhandler) {
    ldout(cct, 1) << "ERROR: No Key handler found: " << error << dendl;
    return std::make_tuple(0, secret);
  }

  ceph::bufferlist in;
  ceph::bufferlist out;

  using ceph::encode;
  in.append(secret);

  int ret = keyhandler->encrypt(in, out, &error);
  if (ret < 0) {
    ldout(cct, 1) << "ERROR: fail to encrypt secret: " << error << dendl;
    return std::make_tuple(0, secret);
  }

  ceph::bufferlist out_encoded;
  out.encode_base64(out_encoded);
  return std::make_tuple(key_id_to_use, out_encoded.to_str());
}

} // namespace secret
} // namespace rgw
