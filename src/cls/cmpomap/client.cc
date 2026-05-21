// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2020 Red Hat, Inc
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */

#include "include/rados/librados.hpp"
#include "client.h"
#include "ops.h"

namespace cls::cmpomap {

// Completion handler that decodes cmp_incr/cmp_decr result into a uint64_t
class cmp_incr_completion : public librados::ObjectOperationCompletion {
  uint64_t* result_ptr;
public:
  explicit cmp_incr_completion(uint64_t* ptr) : result_ptr(ptr) {}

  void handle_completion(int r, bufferlist& outbl) override {
    if (r >= 0 && result_ptr && outbl.length() > 0) {
      try {
        auto p = outbl.cbegin();
        using ceph::decode;
        decode(*result_ptr, p);
      } catch (const buffer::error&) {
        // Decoding failed, but we can't propagate the error here
        // The user will get the operation result code
      }
    }
  }
};

int cmp_vals(librados::ObjectReadOperation& op,
             Mode mode, Op comparison, ComparisonMap values,
             std::optional<ceph::bufferlist> default_value)
{
  if (values.size() > max_keys) {
    return -E2BIG;
  }
  cmp_vals_op call;
  call.mode = mode;
  call.comparison = comparison;
  call.values = std::move(values);
  call.default_value = std::move(default_value);

  bufferlist in;
  encode(call, in);
  op.exec(method::cmp_vals, in);
  return 0;
}

int cmp_set_vals(librados::ObjectWriteOperation& op,
                 Mode mode, Op comparison, ComparisonMap values,
                 std::optional<ceph::bufferlist> default_value)
{
  if (values.size() > max_keys) {
    return -E2BIG;
  }
  cmp_set_vals_op call;
  call.mode = mode;
  call.comparison = comparison;
  call.values = std::move(values);
  call.default_value = std::move(default_value);

  bufferlist in;
  encode(call, in);
  op.exec(method::cmp_set_vals, in);
  return 0;
}

int cmp_set_vals2(librados::ObjectWriteOperation& op,
                 Mode mode, Op comparison, ComparisonMap cmp_values,
                 ValueMap set_values,
                 std::optional<ceph::bufferlist> default_value)
{
  if (cmp_values.size() > max_keys || set_values.size() > max_keys) {
    return -E2BIG;
  }
  cmp_set_vals2_op call;
  call.mode = mode;
  call.comparison = comparison;
  call.cmp_values = std::move(cmp_values);
  call.set_values = std::move(set_values);
  call.default_value = std::move(default_value);

  bufferlist in;
  encode(call, in);
  op.exec(method::cmp_set_vals2, in);
  return 0;
}


int cmp_rm_keys(librados::ObjectWriteOperation& op,
                Mode mode, Op comparison, ComparisonMap values)
{
  if (values.size() > max_keys) {
    return -E2BIG;
  }
  cmp_rm_keys_op call;
  call.mode = mode;
  call.comparison = comparison;
  call.values = std::move(values);

  bufferlist in;
  encode(call, in);
  op.exec(method::cmp_rm_keys, in);
  return 0;
}

int cmp_rm_keys2(librados::ObjectWriteOperation& op,
                Mode mode, Op comparison, ComparisonMap cmp_values,
                KeySet rm_keys,
                std::optional<ceph::bufferlist> default_value)
{
  if (cmp_values.size() > max_keys || rm_keys.size() > max_keys) {
    return -E2BIG;
  }
  cmp_rm_keys2_op call;
  call.mode = mode;
  call.comparison = comparison;
  call.cmp_values = std::move(cmp_values);
  call.rm_keys = std::move(rm_keys);
  call.default_value = std::move(default_value);

  bufferlist in;
  encode(call, in);
  op.exec(method::cmp_rm_keys2, in);
  return 0;
}

int cmp_incr(librados::ObjectWriteOperation& op,
             Op comparison, ComparisonMap cmp_values,
             int64_t increment, const std::string& incr_key,
             std::optional<uint64_t> default_value,
             uint64_t* result)
{
  if (increment == 0) {
    return -EINVAL; // Incorrect use of the function
  }
  if (cmp_values.size() > max_keys) {
    return -E2BIG;
  }
  cmp_incr_op call;
  call.comparison = comparison;
  call.cmp_values = std::move(cmp_values);
  call.incr = increment;
  call.incr_key = incr_key;
  call.default_value = default_value;

  bufferlist in;
  encode(call, in);

  if (result) {
    // If caller wants the result, use a completion that will decode it
    librados::ObjectOperationCompletion* completion = new cmp_incr_completion(result);
    op.exec(method::cmp_incr, in, completion);
  } else {
    op.exec(method::cmp_incr, in);
  }
  return 0;
}

int cmp_decr(librados::ObjectWriteOperation& op,
             Op comparison, ComparisonMap cmp_values,
             uint64_t decrement, const std::string& decr_key,
             std::optional<uint64_t> default_value,
             uint64_t* result)
{
  // Call cmp_incr with negated delta
  return cmp_incr(op, comparison, std::move(cmp_values), (int64_t)-decrement,
                  decr_key, default_value, result);
}

} // namespace cls::cmpomap
