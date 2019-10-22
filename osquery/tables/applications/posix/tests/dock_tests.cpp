/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <gflags/gflags.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class DockerTablesTests : public testing::Test {};

TEST_F(DockerTablesTests, test_signature) {
  SQL results("select tags, repo_digests, parent_id, signer_id, root_id, repository_id from docker_images");

  EXPECT_GE(results.rows().size(), 0U);
  EXPECT_FALSE(results.rows()[0].at("tags").empty());
  EXPECT_TRUE(results.rows()[0].at("parent_id").size() == 0U || results.rows()[0].at("parent_id").size() == 64U);
  EXPECT_TRUE(results.rows()[0].at("signer_id").size() == 0U || results.rows()[0].at("signer_id").size() == 64U);
  EXPECT_TRUE(results.rows()[0].at("root_id").size() == 0U || results.rows()[0].at("root_id").size() == 64U);
  EXPECT_TRUE(results.rows()[0].at("repository_id").size() == 0U || results.rows()[0].at("repository_id").size() == 64U);
}

}
}
