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

#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
namespace tables {
const int ms_in_1_clk_tck = (1000 / sysconf(_SC_CLK_TCK));

inline std::string getHostProcAttr(const std::string& attr,
                               const std::string& pid) {
  return "/opt/osq/proc/" + pid + "/" + attr;
}

inline std::string readHostProcCMDLine(const std::string& pid) {
  auto attr = getHostProcAttr("cmdline", pid);

  std::string content;
  readFile(attr, content);
  // Remove \0 delimiters.
  std::replace_if(content.begin(),
                  content.end(),
                  [](const char& c) { return c == 0; },
                  ' ');
  // Remove trailing delimiter.
  boost::algorithm::trim(content);
  return content;
}

inline std::string readHostProcLink(const std::string& attr,
                                const std::string& pid) {
  // The exe is a symlink to the binary on-disk.
  auto attr_path = getHostProcAttr(attr, pid);
  char full_path[PATH_MAX] = {0};

  char* link_path = realpath(attr_path.c_str(), full_path);
  if (link_path != nullptr) {
    return std::string(link_path);
  } else if (attr_path.compare(std::string(full_path)) != 0) {
    return std::string(full_path);
  }

  return "";
}

// In the case where the linked binary path ends in " (deleted)", and a file
// actually exists at that path, check whether the inode of that file matches
// the inode of the mapped file in /proc/%pid/maps
Status deletedMatchesHostInode(const std::string& path, const std::string& pid) {
  const std::string maps_path = getHostProcAttr("maps", pid);
  std::string maps_contents;
  auto s = osquery::readFile(maps_path, maps_contents);
  if (!s.ok()) {
    return Status(-1, "Cannot read maps file: " + maps_path);
  }

  // Extract the expected inode of the binary file from /proc/%pid/maps
  boost::smatch what;
  boost::regex expression("([0-9]+)\\h+\\Q" + path + "\\E");
  if (!boost::regex_search(maps_contents, what, expression)) {
    return Status(-1, "Could not find binary inode in maps file: " + maps_path);
  }
  std::string inode = what[1];

  // stat the file at the expected binary path
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    return Status(-1, "Error in stat of binary: " + path);
  }

  // If the inodes match, the binary name actually ends with " (deleted)"
  if (std::to_string(st.st_ino) == inode) {
    return Status(0, "Inodes match");
  } else {
    return Status(1, "Inodes do not match");
  }
}

std::set<std::string> getHostProcList(const QueryContext& context) {
  std::set<std::string> pidlist;
  if (context.constraints.count("pid") > 0 &&
      context.constraints.at("pid").exists(EQUALS)) {
    for (const auto& pid : context.constraints.at("pid").getAll(EQUALS)) {
      if (isDirectory("/opt/osq/proc/" + pid)) {
        pidlist.insert(pid);
      }
    }
  } else {
    osquery::procHostProcesses(pidlist);
  }

  return pidlist;
}

void genHostProcessEnvironment(const std::string& pid, QueryData& results) {
  auto attr = getHostProcAttr("environ", pid);

  std::string content;
  readFile(attr, content);
  const char* variable = content.c_str();

  // Stop at the end of nul-delimited string content.
  while (*variable > 0) {
    auto buf = std::string(variable);
    size_t idx = buf.find_first_of("=");

    Row r;
    r["pid"] = pid;
    r["key"] = buf.substr(0, idx);
    r["value"] = buf.substr(idx + 1);
    results.push_back(r);
    variable += buf.size() + 1;
  }
}

void genHostProcessMap(const std::string& pid, QueryData& results) {
  auto map = getHostProcAttr("maps", pid);

  std::string content;
  readFile(map, content);
  for (auto& line : osquery::split(content, "\n")) {
    auto fields = osquery::split(line, " ");
    // If can't read address, not sure.
    if (fields.size() < 5) {
      continue;
    }

    Row r;
    r["pid"] = pid;
    if (!fields[0].empty()) {
      auto addresses = osquery::split(fields[0], "-");
      if (addresses.size() >= 2) {
        r["start"] = "0x" + addresses[0];
        r["end"] = "0x" + addresses[1];
      } else {
        // Problem with the address format.
        continue;
      }
    }

    r["permissions"] = fields[1];
    auto offset = tryTo<long long>(fields[2], 16);
    r["offset"] = BIGINT((offset) ? offset.take() : -1);
    r["device"] = fields[3];
    r["inode"] = fields[4];

    // Path name must be trimmed.
    if (fields.size() > 5) {
      boost::trim(fields[5]);
      r["path"] = fields[5];
    }

    // BSS with name in pathname.
    r["pseudo"] = (fields[4] == "0" && !r["path"].empty()) ? "1" : "0";
    results.push_back(std::move(r));
  }
}

/**
 *  Output from string parsing /proc/<pid>/status.
 */
struct SimpleHostProcStat : private boost::noncopyable {
 public:
  std::string name;
  std::string real_uid;
  std::string real_gid;
  std::string effective_uid;
  std::string effective_gid;
  std::string saved_uid;
  std::string saved_gid;
  std::string resident_size;
  std::string total_size;
  std::string state;
  std::string parent;
  std::string group;
  std::string nice;
  std::string threads;
  std::string user_time;
  std::string system_time;
  std::string start_time;

  /// For errors processing proc data.
  Status status;

  explicit SimpleHostProcStat(const std::string& pid);
};

SimpleHostProcStat::SimpleHostProcStat(const std::string& pid) {
  std::string content;
  if (readFile(getHostProcAttr("stat", pid), content).ok()) {
    auto start = content.find_last_of(")");
    // Start parsing stats from ") <MODE>..."
    if (start == std::string::npos || content.size() <= start + 2) {
      status = Status(1, "Invalid /proc/stat header");
      return;
    }

    auto details = osquery::split(content.substr(start + 2), " ");
    if (details.size() <= 19) {
      status = Status(1, "Invalid /proc/stat content");
      return;
    }

    this->state = details.at(0);
    this->parent = details.at(1);
    this->group = details.at(2);
    this->user_time = details.at(11);
    this->system_time = details.at(12);
    this->nice = details.at(16);
    this->threads = details.at(17);
    this->start_time = details.at(19); 
  }

  // /proc/N/status may be not available, or readable by this user.
  if (!readFile(getHostProcAttr("status", pid), content).ok()) {
    status = Status(1, "Cannot read /proc/status");
    return;
    }

  for (const auto& line : osquery::split(content, "\n")) {
    // Status lines are formatted: Key: Value....\n.
    auto detail = osquery::split(line, ':', 1);
    if (detail.size() != 2) {
      continue;
    }

    // There are specific fields from each detail.
    if (detail.at(0) == "Name") {
      this->name = detail.at(1);
    } else if (detail.at(0) == "VmRSS") {
      detail[1].erase(detail.at(1).end() - 3, detail.at(1).end());
      // Memory is reported in kB.
      this->resident_size = detail.at(1) + "000";
    } else if (detail.at(0) == "VmSize") {
      detail[1].erase(detail.at(1).end() - 3, detail.at(1).end());
      // Memory is reported in kB.
      this->total_size = detail.at(1) + "000";
    } else if (detail.at(0) == "Gid") {
      // Format is: R E - -
      auto gid_detail = osquery::split(detail.at(1), "\t");
      if (gid_detail.size() == 4) {
        this->real_gid = gid_detail.at(0);
        this->effective_gid = gid_detail.at(1);
        this->saved_gid = gid_detail.at(2);
      }
    } else if (detail.at(0) == "Uid") {
      auto uid_detail = osquery::split(detail.at(1), "\t");
      if (uid_detail.size() == 4) {
        this->real_uid = uid_detail.at(0);
        this->effective_uid = uid_detail.at(1);
        this->saved_uid = uid_detail.at(2);
      }
    }
  }
}

/**
 * Output from string parsing /proc/<pid>/io.
 */
struct SimpleHostProcIo : private boost::noncopyable {
 public:
  std::string read_bytes;
  std::string write_bytes;
  std::string cancelled_write_bytes;

  /// For errors processing proc data.
  Status status;

  explicit SimpleHostProcIo(const std::string& pid);
};

SimpleHostProcIo::SimpleHostProcIo(const std::string& pid) {
  std::string content;
  if (!readFile(getHostProcAttr("io", pid), content).ok()) {
       status = Status(
           1, "Cannot read /opt/osq/proc/" + pid + "/io (is osquery running as root?)");
       return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    // IO lines are formatted: Key: Value....\n.
    auto detail = osquery::split(line, ':', 1);
    if (detail.size() != 2) {
      continue;
    }

    // There are specific fields from each detail
    if (detail.at(0) == "read_bytes") {
      this->read_bytes = detail.at(1);
    } else if (detail.at(0) == "write_bytes") {
      this->write_bytes = detail.at(1);
    } else if (detail.at(0) == "cancelled_write_bytes") {
      this->cancelled_write_bytes = detail.at(1);
    }
  }
}

/**
 * @brief Determine if the process path (binary) exists on the filesystem.
 *
 * If the path of the executable that started the process is available and
 * the path exists on disk, set on_disk to 1. If the path is not
 * available, set on_disk to -1. If, and only if, the path of the
 * executable is available and the file does NOT exist on disk, set on_disk
 * to 0.
 *
 * @param pid The string (because we're referencing file path) pid.
 * @param path A mutable string found from /proc/N/exe. If this is found
 *             to contain the (deleted) suffix, it will be removed.
 * @return A tristate -1 error, 1 yes, 0 nope.
 */
int getOnHostDisk(const std::string& pid, std::string& path) {
  if (path.empty()) {
    return -1;
  }

  // The string appended to the exe path when the binary is deleted
  const std::string kDeletedString = " (deleted)";
  if (!boost::algorithm::ends_with(path, kDeletedString)) {
    return (osquery::pathExists(path)) ? 1 : 0;
  }

  if (!osquery::pathExists(path)) {
    // No file exists with the path including " (deleted)", so we can strip
    // this from the path and set on_disk = 0
    path.erase(path.size() - kDeletedString.size());
    return 0;
  }

  // Special case in which we have to check the inode to see whether the
  // process is actually running from a binary file ending with
  // " (deleted)". See #1607
  std::string maps_contents;
  Status deleted = deletedMatchesHostInode(path, pid);
  if (deleted.getCode() == -1) {
    LOG(ERROR) << deleted.getMessage();
    return -1;
  } else if (deleted.getCode() == 0) {
    // The process is actually running from a binary ending with
    // " (deleted)"
    return 1;
  } else {
    // There is a collision with a file name ending in " (deleted)", but
    // that file is not the binary for this process
    path.erase(path.size() - kDeletedString.size());
    return 0;
  }
}

void genHostProcess(const std::string& pid,
                    long system_boot_time,
                    QueryData& results) {
  // Parse the process stat and status.
  SimpleHostProcStat proc_stat(pid);
  // Parse the process io
  SimpleHostProcIo proc_io(pid);

  if (!proc_stat.status.ok()) {
    VLOG(1) << proc_stat.status.getMessage() << " for pid " << pid;
    return;
  }

  Row r;
  r["pid"] = pid;
  r["parent"] = proc_stat.parent;
  r["path"] = readHostProcLink("exe", pid);
  r["name"] = proc_stat.name;
  r["pgroup"] = proc_stat.group;
  r["state"] = proc_stat.state;
  r["nice"] = proc_stat.nice;
  r["threads"] = proc_stat.threads;
  // Read/parse cmdline arguments.
  r["cmdline"] = readHostProcCMDLine(pid);
  r["cwd"] = readHostProcLink("cwd", pid);
  r["root"] = readHostProcLink("root", pid);
  r["uid"] = proc_stat.real_uid;
  r["euid"] = proc_stat.effective_uid;
  r["suid"] = proc_stat.saved_uid;
  r["gid"] = proc_stat.real_gid;
  r["egid"] = proc_stat.effective_gid;
  r["sgid"] = proc_stat.saved_gid;

  r["on_disk"] = INTEGER(getOnHostDisk(pid, r["path"]));

  // size/memory information
  r["wired_size"] = "0"; // No support for unpagable counters in linux.
  r["resident_size"] = proc_stat.resident_size;
  r["total_size"] = proc_stat.total_size;

  // time information
  auto usr_time = std::strtoull(proc_stat.user_time.data(), nullptr, 10);
  r["user_time"] = std::to_string(usr_time * ms_in_1_clk_tck);

  auto sys_time = std::strtoull(proc_stat.system_time.data(), nullptr, 10);
  r["system_time"] = std::to_string(sys_time * ms_in_1_clk_tck);
  ;

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

  auto pidlist = getHostProcList(context);
  for (const auto& pid : pidlist) {
    genHostProcess(pid, system_boot_time, results);
  }

  return results;
}

QueryData genHostProcessEnvs(QueryContext& context) {
  QueryData results;

  auto pidlist = getHostProcList(context);
  for (const auto& pid : pidlist) {
    genHostProcessEnvironment(pid, results);
  }

  return results;
}

QueryData genHostProcessMemoryMap(QueryContext& context) {
  QueryData results;

  auto pidlist = getHostProcList(context);
  for (const auto& pid : pidlist) {
    genHostProcessMap(pid, results);
  }

  return results;
}
}
}
