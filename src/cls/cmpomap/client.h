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

#pragma once

#include <optional>
#include "include/rados/librados_fwd.hpp"
#include "types.h"

namespace cls::cmpomap {

/// requests with too many key comparisons will be rejected with -E2BIG
static constexpr uint32_t max_keys = 1000;

/// process each of the omap value comparisons according to the same rules as
/// cmpxattr(), and return -ECANCELED if a comparison is unsuccessful. for
/// comparisons with Mode::U64, failure to decode an input value is reported
/// as -EINVAL, an empty stored value is compared as 0, and failure to decode
/// a stored value is reported as -EIO
[[nodiscard]] int cmp_vals(librados::ObjectReadOperation& op,
                           Mode mode, Op comparison, ComparisonMap values,
                           std::optional<ceph::bufferlist> default_value);

/// process each of the omap value comparisons according to the same rules as
/// cmpxattr(). any key/value pairs that compare successfully are overwritten
/// with the corresponding input value. for comparisons with Mode::U64, failure
/// to decode an input value is reported as -EINVAL. an empty stored value is
/// compared as 0, while decode failure of a stored value is treated as an
/// unsuccessful comparison and is not reported as an error
[[nodiscard]] int cmp_set_vals(librados::ObjectWriteOperation& writeop,
                               Mode mode, Op comparison, ComparisonMap values,
                               std::optional<ceph::bufferlist> default_value);

/// process all of the omap value comparisons according to the same rules as
/// cmpxattr(). If all key/value pairs for comparison purpose compare successfully,
/// the key/value pairs for overwritten are overwritten. For comparisons with
/// Mode::U64, failure to decode an input value is reported as -EINVAL. An empty
/// stored value is compared as 0, while decode failure of a stored value is treated
/// as an unsuccessful comparison and is not reported as an error.
[[nodiscard]] int cmp_set_vals2(librados::ObjectWriteOperation& writeop,
                                Mode mode, Op comparison, ComparisonMap cmp_values,
                                ValueMap set_values,
                                std::optional<ceph::bufferlist> default_value);

/// process each of the omap value comparisons according to the same rules as
/// cmpxattr(). any key/value pairs that compare successfully are removed. for
/// comparisons with Mode::U64, failure to decode an input value is reported as
/// -EINVAL. an empty stored value is compared as 0, while decode failure of a
/// stored value is treated as an unsuccessful comparison and is not reported
/// as an error
[[nodiscard]] int cmp_rm_keys(librados::ObjectWriteOperation& writeop,
                              Mode mode, Op comparison, ComparisonMap values);

/// process all of the omap value comparisons according to the same rules as
/// cmpxattr(). If all key/value pairs for comparison purpose compare successfully,
/// the key set for deletion are deleted. For comparisons with
/// Mode::U64, failure to decode an input value is reported as -EINVAL. An empty
/// stored value is compared as 0, while decode failure of a stored value is treated
/// as an unsuccessful comparison and is not reported as an error.
[[nodiscard]] int cmp_rm_keys2(librados::ObjectWriteOperation& writeop,
                               Mode mode, Op comparison, ComparisonMap cmp_values,
                               KeySet rm_keys,
                               std::optional<ceph::bufferlist> default_value);

/// This function is only applied for U64 mode.
/// Process all of the omap value comparisons according to the same rules as
/// cmpxattr(). If all key/value pairs for comparison purpose compare successfully,
/// the value of the key for increment is updated based on the increment provided.
/// Failure to decode an input value is reported as -EINVAL. An empty
/// stored value is compared as 0, while decode failure of a stored value is treated
/// as an unsuccessful comparison and is not reported as an error.
/// If result is provided, the updated value will be stored in *result after
/// ioctx.operate() completes successfully. The caller should check the return code
/// from ioctx.operate() before using the result value.
/// IMPORTANT: When requesting a result, you must pass librados::OPERATION_RETURNVEC
/// flag to ioctx.operate() to enable return data from write operations:
///   ioctx.operate(oid, &op, librados::OPERATION_RETURNVEC);
/// Without this flag, the output bufferlist will be empty and result will not be set.
/// If default_value is provided, missing keys (both comparison and update keys)
/// will use this value instead of 0.
[[nodiscard]] int cmp_incr(librados::ObjectWriteOperation& writeop,
                           Op comparison, ComparisonMap cmp_values,
                           int64_t increment, const std::string& incr_key,
                           std::optional<uint64_t> default_value = std::nullopt,
                           uint64_t* result = nullptr);

/// This function is only applied for U64 mode.
/// Process all of the omap value comparisons according to the same rules as
/// cmpxattr(). If all key/value pairs for comparison purpose compare successfully,
/// the value of the key for update is decremented based on the decrement delta provided.
/// This is a convenience wrapper around cmp_incr that negates the delta.
/// Failure to decode an input value is reported as -EINVAL. An empty
/// stored value is compared as 0, while decode failure of a stored value is treated
/// as an unsuccessful comparison and is not reported as an error.
/// If result is provided, the updated value will be stored in *result after
/// ioctx.operate() completes successfully. The caller should check the return code
/// from ioctx.operate() before using the result value.
/// IMPORTANT: When requesting a result, you must pass librados::OPERATION_RETURNVEC
/// flag to ioctx.operate() to enable return data from write operations:
///   ioctx.operate(oid, &op, librados::OPERATION_RETURNVEC);
/// Without this flag, the output bufferlist will be empty and result will not be set.
/// If default_value is provided, missing keys (both comparison and update keys)
/// will use this value instead of 0.
[[nodiscard]] int cmp_decr(librados::ObjectWriteOperation& writeop,
                           Op comparison, ComparisonMap cmp_values,
                           uint64_t decrement, const std::string& decr_key,
                           std::optional<uint64_t> default_value = std::nullopt,
                           uint64_t* result = nullptr);

// bufferlist factories for comparison values
inline ceph::bufferlist string_buffer(std::string_view value) {
  ceph::bufferlist bl;
  bl.append(value);
  return bl;
}
inline ceph::bufferlist u64_buffer(uint64_t value) {
  ceph::bufferlist bl;
  using ceph::encode;
  encode(value, bl);
  return bl;
}

} // namespace cls::cmpomap
