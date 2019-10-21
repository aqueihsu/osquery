#include <stdlib.h>
#include <string>
#include <unistd.h>

namespace osquery {
namespace tables {

const int kMSIn1CLKTCK = (1000 / sysconf(_SC_CLK_TCK));

inline std::string getProcAttr(const std::string& proc_path,
                               const std::string& attr,
                               const std::string& pid) {
  return proc_path + pid + "/" + attr;
}

inline std::string readProcCMDLine(const std::string& proc_path,
                                   const std::string& pid) {
  auto attr = getProcAttr(proc_path, "cmdline", pid);

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

inline std::string readProcLink(const std::string& proc_path,
                                const std::string& attr,
                                const std::string& pid) {
  // The exe is a symlink to the binary on-disk.
  auto attr_path = getProcAttr(proc_path, attr, pid);

  std::string result = "";
  struct stat sb;
  if (lstat(attr_path.c_str(), &sb) != -1) {
    // Some symlinks may report 'st_size' as zero
    // Use PATH_MAX as best guess
    // For cases when 'st_size' is not zero but smaller than
    // PATH_MAX we will still use PATH_MAX to minimize chance
    // of output trucation during race condition
    ssize_t buf_size = sb.st_size < PATH_MAX ? PATH_MAX : sb.st_size;
    // +1 for \0, since readlink does not append a null
    char* linkname = static_cast<char*>(malloc(buf_size + 1));
    ssize_t r = readlink(attr_path.c_str(), linkname, buf_size);

    if (r > 0) { // Success check
      // r may not be equal to buf_size
      // if r == buf_size there was race condition
      // and link is longer than buf_size and because of this
      // truncated
      linkname[r] = '\0';
      result = std::string(linkname);
    }
    free(linkname);
  }

  return result;
}

/**
 *  Output from string parsing /proc/<pid>/status.
 */
struct SimpleProcStat : private boost::noncopyable {
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

  explicit SimpleProcStat(const std::string& proc_path, const std::string& pid);
};

/**
 * Output from string parsing /proc/<pid>/io.
 */
struct SimpleProcIo : private boost::noncopyable {
 public:
  std::string read_bytes;
  std::string write_bytes;
  std::string cancelled_write_bytes;

  /// For errors processing proc data.
  Status status;

  explicit SimpleProcIo(const std::string& proc_path, const std::string& pid);
};

int getOnDisk(const std::string& proc_path, const std::string& pid, std::string& path);
std::set<std::string> getProcList(const std::string& proc_path, const QueryContext& context);

void genProcessEnvironment(const std::string& proc_path, const std::string& pid, QueryData& results);
void genProcessMap(const std::string& proc_path, const std::string& pid, QueryData& result);

}
}

