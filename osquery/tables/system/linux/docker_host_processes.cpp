/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <map>
#include <string>

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/noncopyable.hpp>
#include <boost/regex.hpp>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include <osquery/tables/system/linux/processes.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
namespace tables {

const std::string& HOST_PROC_PATH = "/opt/osq/proc/";

void genHostProcess(const std::string& pid,
                    long system_boot_time,
                    QueryData& results) {
  // Parse the process stat and status.
  SimpleProcStat proc_stat(HOST_PROC_PATH, pid);
  // Parse the process io
  SimpleProcIo proc_io(HOST_PROC_PATH, pid);

  if (!proc_stat.status.ok()) {
    VLOG(1) << proc_stat.status.getMessage() << " for pid " << pid;
    return;
  }

  Row r;
  r["pid"] = pid;
  r["parent"] = proc_stat.parent;
  r["path"] = readProcLink(HOST_PROC_PATH, "exe", pid);
  r["name"] = proc_stat.name;
  r["pgroup"] = proc_stat.group;
  r["state"] = proc_stat.state;
  r["nice"] = proc_stat.nice;
  r["threads"] = proc_stat.threads;
  // Read/parse cmdline arguments.
  r["cmdline"] = readProcCMDLine(HOST_PROC_PATH, pid);
  r["cwd"] = readProcLink(HOST_PROC_PATH, "cwd", pid);
  r["root"] = readProcLink(HOST_PROC_PATH, "root", pid);
  r["uid"] = proc_stat.real_uid;
  r["euid"] = proc_stat.effective_uid;
  r["suid"] = proc_stat.saved_uid;
  r["gid"] = proc_stat.real_gid;
  r["egid"] = proc_stat.effective_gid;
  r["sgid"] = proc_stat.saved_gid;

  r["on_disk"] = INTEGER(getOnDisk(HOST_PROC_PATH, pid, r["path"]));

  // size/memory information
  r["wired_size"] = "0"; // No support for unpagable counters in linux.
  r["resident_size"] = proc_stat.resident_size;
  r["total_size"] = proc_stat.total_size;

  // time information
  auto usr_time = std::strtoull(proc_stat.user_time.data(), nullptr, 10);
  r["user_time"] = std::to_string(usr_time * kMSIn1CLKTCK);

  auto sys_time = std::strtoull(proc_stat.system_time.data(), nullptr, 10);
  r["system_time"] = std::to_string(sys_time * kMSIn1CLKTCK);

  auto proc_start_time_exp = tryTo<long>(proc_stat.start_time);
  if (proc_start_time_exp.isValue() && system_boot_time > 0) {
    r["start_time"] = INTEGER(system_boot_time + proc_start_time_exp.take() /
                                                     sysconf(_SC_CLK_TCK));
  } else {
    r["start_time"] = "-1";
  }

  if (!proc_io.status.ok()) {
    // /proc/<pid>/io can require root to access, so don't fail if we can't
    VLOG(1) << proc_io.status.getMessage();
  } else {
    r["disk_bytes_read"] = proc_io.read_bytes;

    long long write_bytes = tryTo<long long>(proc_io.write_bytes).takeOr(0ll);
    long long cancelled_write_bytes =
        tryTo<long long>(proc_io.cancelled_write_bytes).takeOr(0ll);

    r["disk_bytes_written"] =
        std::to_string(write_bytes - cancelled_write_bytes);
  }

  results.push_back(r);
}

QueryData genHostProcesses(QueryContext& context) {
  QueryData results;
  auto system_boot_time = getUptime();
  if (system_boot_time > 0) {		
    system_boot_time = std::time(nullptr) - system_boot_time;		
  }

  auto pidlist = getProcList(HOST_PROC_PATH, context);
  for (const auto& pid : pidlist) {
    genHostProcess(pid, system_boot_time, results);
  }

  return results;
}

QueryData genHostProcessEnvs(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(HOST_PROC_PATH, context);
  for (const auto& pid : pidlist) {
    genProcessEnvironment(HOST_PROC_PATH, pid, results);
  }

  return results;
}

QueryData genHostProcessMemoryMap(QueryContext& context) {
  QueryData results;

  auto pidlist = getProcList(HOST_PROC_PATH, context);
  for (const auto& pid : pidlist) {
    genProcessMap(HOST_PROC_PATH, pid, results);
  }

  return results;
}

}
}
