// License info?
// Scythe plugin - interface to Scythe and Crossroads devices

#ifndef PI_SCYTHE_HPP
#define PI_SCYTHE_HPP

#include <climits>
#include <regex>
#include <string>
#include <variant>

#include <spire.hpp>
#include "sycl/detail/pi.h"

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

struct _pi_event {
  size_t kernel_id;
  bool is_buffer; //buffer events done immediately
  _pi_event() : is_buffer(false) {}
  _pi_event(bool is_buffer) : is_buffer(is_buffer) {}

  pi_int32 get_execution_status() const noexcept {
    if (is_buffer) {
      return PI_EVENT_COMPLETE;
    }
    else {
      if (spire::global_interpreter.is_done(kernel_id)) {
        return PI_EVENT_COMPLETE;
      }
      else {
        return PI_EVENT_RUNNING;
      }
    }
  }
};

struct _pi_mem {
  spire::MemBuffer mem;
  int refcount;

  _pi_mem() : refcount(1) {}

  void set(int id, size_t size) {
    mem.size = size;
    mem.id = id;
  }

  int inc_ref() {
    return ++refcount;
  }

  int dec_ref() {
    return --refcount;
  }
};

struct _pi_context {

};

struct _pi_queue {
  _pi_context* context;

  _pi_queue(_pi_context* c) : context(c) {}
};

struct _pi_program {
  spire::Program program;
  _pi_context* context;
  int refcount;

  _pi_program(_pi_context* context, const void* il, size_t length) 
    : program(il, length), context(context), refcount(1) {}

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


struct _pi_kernel {
  spire::Kernel& kernel;
  _pi_program* program;
  int refcount;
  
  _pi_kernel(_pi_program* program, const char* n) 
    : kernel(program->program.find_kernel({n})), program(program), refcount(1) {}

  int inc_ref() {
    return ++refcount;
  }

  int dec_ref() {
    return --refcount;
  }

  void bind_membuffer_arg(size_t arg_idx, int mem_buffer_id) {
    std::cerr << "Bind arg: " << arg_idx << " size " << kernel.function.params.size() << std::endl;
    kernel.function.params[arg_idx].mem_buffer_id = mem_buffer_id;
  };
};
#endif // PI_SCYTHE_HPP
