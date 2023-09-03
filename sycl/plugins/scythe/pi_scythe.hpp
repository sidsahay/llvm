// License info?
// Scythe plugin - interface to Scythe and Crossroads devices

#ifndef PI_SCYTHE_HPP
#define PI_SCYTHE_HPP

#include <climits>
#include <regex>
#include <string>

#include <spire.hpp>

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

struct _pi_program {
  spire::Program program;
  int refcount;

  _pi_program(const void* il, size_t length) 
    : program(il, length), refcount(1) {}

  int inc_ref() {
    return ++refcount;
  }

  int dec_ref() {
    return --refcount;
  }

  void build() {
    program.parse_and_build();
  }
};

#endif // PI_SCYTHE_HPP
