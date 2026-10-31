#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>
#define FILE_WRITE "w"
#define FILE_APPEND "a"
namespace fs {
struct Backend {
  std::map<std::string, std::vector<uint8_t>> files;
  bool directory = false, failOpen = false, failMkdir = false;
  size_t maxWrite = size_t(-1);
  unsigned writes = 0;
};
class File {
 public:
  File() = default;
  File(Backend* b, std::string path): backend(b), name(path), live(new bool(true)) {}
  explicit operator bool() const { return backend && live && *live; }
  size_t write(const uint8_t* p, size_t n) {
    if (!*this) return 0;
    n = std::min(n, backend->maxWrite);
    backend->files[name].insert(backend->files[name].end(), p, p + n); ++backend->writes; return n;
  }
  void flush() {}
  void close() { if (live) *live = false; }
 private:
  Backend* backend = nullptr;
  std::string name;
  std::shared_ptr<bool> live;
};
class FS {
 public:
  Backend state;
  bool exists(const char* p) { return std::string(p) == "/pcap" ? state.directory : state.files.count(p); }
  bool mkdir(const char*) { if (state.failMkdir) return false; state.directory = true; return true; }
  File open(const char* p, const char* mode) { if (state.failOpen) return {}; if (std::string(mode) == FILE_WRITE) state.files[p] = {}; else state.files[p]; return File(&state, p); }
};
}
using fs::File;
