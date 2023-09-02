// License info?
// Scythe plugin - interface to Scythe and Crossroads devices

#ifndef PI_SCYTHE_HPP
#define PI_SCYTHE_HPP

#include <climits>
#include <regex>
#include <string>

// This version should be incremented for any change made to this file or its
// corresponding .cpp file.
#define _PI_SCYTHE_PLUGIN_VERSION 1

#define _PI_SCYTHE_PLUGIN_VERSION_STRING                                       \
  _PI_PLUGIN_VERSION_STRING(_PI_SCYTHE_PLUGIN_VERSION)

struct _pi_ext_command_buffer {};

struct _pi_device {
  std::string name;
  _pi_device(const std::string& name) : name(name) {}
};

// There are two platforms, Scythe and XRD
// We make corresponding global platform instances
// One device per platform
struct _pi_platform {
  std::string name;
  std::unique_ptr<_pi_device> device;
};

struct _pi_mem {
  int id;
  size_t size;
};

// TODO: rename to _pi_program
struct ScytheProgram {
  size_t length;
  uint8_t* bytes;

  ScytheProgram(size_t spirv_length, const void* spirv_bytes) 
    : length(spirv_length) {
      bytes = new uint8_t[length];
      memcpy(bytes, spirv_bytes, length);
  }

  ~ScytheProgram() {
    delete[] bytes;
  }
};

#endif // PI_SCYTHE_HPP
