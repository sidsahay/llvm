//==---------- pi_scythe.cpp - Scythe Plugin -------------------------------==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
/// \defgroup sycl_pi_scythe Scythe Plugin
/// \ingroup sycl_pi

/// \file pi_scythe.cpp
/// Implementation of Scythe Plugin. It is the interface between device-agnostic
/// SYCL runtime layer and underlying Scythe runtime.
///
/// \ingroup sycl_pi_scythe

#include <pi_scythe.hpp>
// #include <sycl/detail/cl.h>
#include <sycl/detail/iostream_proxy.hpp>
#include <sycl/detail/pi.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <fstream>

#include "spirv-tools/libspirv.hpp"

#define SCYTHE_DEBUG

#ifdef SCYTHE_DEBUG
  #define S {std::cerr << "[Log] " << __FUNCTION__ << std::endl; }
#else
  #define S {}
#endif

// very useful getInfo template from HIP plugin
namespace blah {

  // buffer counter so that we can ID and release membuffers
  static int buffer_count = 0;

  template <typename T, typename Assign>
pi_result getInfoImpl(size_t param_value_size, void *param_value,
                      size_t *param_value_size_ret, T value, size_t value_size,
                      Assign &&assign_func) {

  if (param_value != nullptr) {

    if (param_value_size < value_size) {
      return PI_ERROR_INVALID_VALUE;
    }

    assign_func(param_value, value, value_size);
  }

  if (param_value_size_ret != nullptr) {
    *param_value_size_ret = value_size;
  }

  return PI_SUCCESS;
}

template <typename T>
pi_result getInfo(size_t param_value_size, void *param_value,
                  size_t *param_value_size_ret, T value) {

  auto assignment = [](void *param_value, T value, size_t value_size) {
    (void)value_size;
    *static_cast<T *>(param_value) = value;
  };

  return getInfoImpl(param_value_size, param_value, param_value_size_ret, value,
                     sizeof(T), std::move(assignment));
}

template <typename T>
pi_result getInfoArray(size_t array_length, size_t param_value_size,
                       void *param_value, size_t *param_value_size_ret,
                       T *value) {

  auto assignment = [](void *param_value, T *value, size_t value_size) {
    memcpy(param_value, static_cast<const void *>(value), value_size);
  };

  return getInfoImpl(param_value_size, param_value, param_value_size_ret, value,
                     array_length * sizeof(T), std::move(assignment));
}

template <>
pi_result getInfo<const char *>(size_t param_value_size, void *param_value,
                                size_t *param_value_size_ret,
                                const char *value) {
  return getInfoArray(strlen(value) + 1, param_value_size, param_value,
                      param_value_size_ret, value);
}
}

// Global variables for PI_ERROR_PLUGIN_SPECIFIC_ERROR
constexpr size_t MaxMessageSize = 256;
thread_local pi_result ErrorMessageCode = PI_SUCCESS;
thread_local char ErrorMessage[MaxMessageSize];

// Global platform variables
constexpr int NUM_SCYTHE_PLATFORMS = 2;

// Utility function for setting a message and warning
[[maybe_unused]] static void setErrorMessage(const char *message,
                                             pi_result error_code) {
  assert(strlen(message) <= MaxMessageSize);
  strcpy(ErrorMessage, message);
  S
  ErrorMessageCode = error_code;
}

// Returns plugin specific error and warning messages
pi_result piPluginGetLastError(char **message) {
  *message = &ErrorMessage[0];
  S
  return ErrorMessageCode;
}

// Returns plugin specific backend option.
pi_result piPluginGetBackendOption(pi_platform, const char *frontend_option,
                                   const char **backend_option) {
S
  // TODO
  using namespace std::literals;
  if (frontend_option == nullptr)
    return PI_ERROR_INVALID_VALUE;
  std::cout << "[piPluginGetBackendOption] frontend: " << frontend_option << "\n";
  if (frontend_option == ""sv) {
    *backend_option = "";
    return PI_SUCCESS;
  }
  else {
       *backend_option = "";
    return PI_SUCCESS;
  }
}

// nothing is implemented
extern "C" {

pi_result piDeviceGetInfo(pi_device device, pi_device_info param_name,
                          size_t param_value_size, void *param_value,
                          size_t *param_value_size_ret) {
                            S

  #ifdef SCYTHE_DEBUG
    std::cerr << param_name << std::endl;
  #endif

  switch (param_name) {
    case PI_DEVICE_INFO_TYPE: 
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   PI_DEVICE_TYPE_ACC);
    case PI_DEVICE_INFO_NAME:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   device->name.c_str());
    case PI_DEVICE_INFO_VENDOR:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   "CMU-Intel Scythe Research Project");
    case PI_DEVICE_INFO_PARENT_DEVICE:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   nullptr);
    case PI_DEVICE_INFO_EXTENSIONS:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   "cl_khr_fp64");
    case PI_DEVICE_INFO_HOST_UNIFIED_MEMORY:
    case PI_DEVICE_INFO_BUILD_ON_SUBDEVICE:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   PI_FALSE);
    case PI_DEVICE_INFO_COMPILER_AVAILABLE:
      return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   PI_TRUE);

    default:
      return PI_ERROR_INVALID_VALUE;
  }
}

// from HIP plugin
pi_result piPlatformsGet(pi_uint32 num_entries, pi_platform *platforms,
                         pi_uint32 *num_platforms) {
                          S
    static std::once_flag initFlag;
    static pi_uint32 numPlatforms = NUM_SCYTHE_PLATFORMS;
    static std::vector<_pi_platform> platformIds;

    if (num_entries == 0 and platforms != nullptr) {
      return PI_ERROR_INVALID_VALUE;
    }
    if (platforms == nullptr and num_platforms == nullptr) {
      return PI_ERROR_INVALID_VALUE;
    }

    pi_result err = PI_SUCCESS;

    std::call_once(
        initFlag,
        [](pi_result &err) {
            numPlatforms = NUM_SCYTHE_PLATFORMS;
            platformIds.resize(numPlatforms);

            platformIds[0].name = "Scythe Platform";
            platformIds[0].device = std::make_unique<_pi_device>("Scythe Device");

            platformIds[1].name = "Crossroads Platform";
            platformIds[1].device = std::make_unique<_pi_device>("Crossroads Device");
          
        },
        err);

    if (num_platforms != nullptr) {
      *num_platforms = numPlatforms;
    }

    if (platforms != nullptr) {
      for (unsigned i = 0; i < std::min(num_entries, numPlatforms); ++i) {
        platforms[i] = &platformIds[i];
      }
    }

    return err;
  
}


pi_result piPlatformGetInfo(pi_platform platform, pi_platform_info param_name,
                            size_t param_value_size, void *param_value,
                            size_t *param_value_size_ret) {
                              S

  switch (param_name) {
  case PI_PLATFORM_INFO_NAME:
    return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   platform->name.c_str());
  case PI_PLATFORM_INFO_VENDOR:
    return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   "CMU-Intel Scythe Research");
  case PI_PLATFORM_INFO_PROFILE:
    return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   "FULL PROFILE");
  case PI_PLATFORM_INFO_VERSION: {
    return blah::getInfo(param_value_size, param_value, param_value_size_ret,
                   "1.0");
  }
  case PI_PLATFORM_INFO_EXTENSIONS: {
    return blah::getInfo(param_value_size, param_value, param_value_size_ret, "");
  }
  case PI_EXT_PLATFORM_INFO_BACKEND: {
    return blah::getInfo<pi_platform_backend>(param_value_size, param_value,
                                        param_value_size_ret,
                                        PI_EXT_PLATFORM_BACKEND_SCYTHE);
  }
  default:
    return PI_ERROR_INVALID_VALUE;
  }
}

pi_result piextPlatformCreateWithNativeHandle(pi_native_handle nativeHandle,
                                              pi_platform *platform) {
                                                S
  return PI_ERROR_INVALID_OPERATION;
}

// Adapted from HIP plugin
pi_result piDevicesGet(pi_platform platform, pi_device_type device_type,
                       pi_uint32 num_entries, pi_device *devices,
                       pi_uint32 *num_devices) {
                        S
  pi_result err = PI_SUCCESS;
  // only respond to Default or Accelerator queries
  const bool askingForDefault = device_type == PI_DEVICE_TYPE_DEFAULT;
  const bool askingForAcc = device_type & PI_DEVICE_TYPE_ACC;
  const bool returnDevices = askingForDefault || askingForAcc;

  // One device per platform for now
  size_t numDevices = returnDevices ? 1 : 0;

  if (num_devices) {
    *num_devices = numDevices;
  }

  if (returnDevices && devices) {
    devices[0] = platform->device.get();
  }

  return err;
}

pi_result piextDeviceSelectBinary(pi_device device, pi_device_binary *images,
                                  pi_uint32 num_images,
                                  pi_uint32 *selected_image_ind) {
                                    S
  // TODO: are pipes gated by this?
  const char *image_target = __SYCL_PI_DEVICE_BINARY_TARGET_SPIRV64_FPGA;
  constexpr pi_uint32 invalid_ind = std::numeric_limits<pi_uint32>::max();

  // Find the appropriate device image, fallback to spirv if not found
  pi_uint32 fallback = invalid_ind;
  for (pi_uint32 i = 0; i < num_images; ++i) {
    if (strcmp(images[i]->DeviceTargetSpec, image_target) == 0) {
      *selected_image_ind = i;
      return PI_SUCCESS;
    }
    if (strcmp(images[i]->DeviceTargetSpec,
               __SYCL_PI_DEVICE_BINARY_TARGET_SPIRV64) == 0)
      fallback = i;
  }
  // Points to a spirv image, if such indeed was found
  if ((*selected_image_ind = fallback) != invalid_ind)
    return PI_SUCCESS;
  // No image can be loaded for the given device
  return PI_ERROR_INVALID_BINARY;
}

pi_result piextDeviceCreateWithNativeHandle(pi_native_handle nativeHandle,
                                            pi_platform, pi_device *piDevice) {
                                              S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextQueueCreate(pi_context Context, pi_device Device,
                           pi_queue_properties *Properties, pi_queue *Queue) {
                            S
                            // TODO
  return PI_SUCCESS;
}

pi_result piQueueCreate(pi_context context, pi_device device,
                        pi_queue_properties properties, pi_queue *queue) {
                          S
                          // TODO
  return PI_SUCCESS;
}

pi_result piQueueGetInfo(pi_queue queue, pi_queue_info param_name,
                         size_t param_value_size, void *param_value,
                         size_t *param_value_size_ret) {
                          S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextQueueCreateWithNativeHandle(pi_native_handle nativeHandle,
                                           int32_t NativeHandleDesc, pi_context,
                                           pi_device, bool ownNativeHandle,
                                           pi_queue_properties *Properties,
                                           pi_queue *piQueue) {
                                            S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piProgramCreate(pi_context context, const void *il, size_t length,
                          pi_program *res_program) {
                            S
                            // TODO
  // since we don't manage the memory of il, make a new buffer
  // and just send the spirv right back. The spirv execution
  // engine will take care of actually executing the thing.
  auto program = new ScytheProgram(length, il);
  *res_program = reinterpret_cast<pi_program>(program);
  return PI_SUCCESS;
}

pi_result piextProgramCreateWithNativeHandle(pi_native_handle nativeHandle,
                                             pi_context, bool,
                                             pi_program *piProgram) {
                                              S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piSamplerCreate(pi_context context,
                          const pi_sampler_properties *sampler_properties,
                          pi_sampler *result_sampler) {
                            S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextKernelSetArgMemObj(pi_kernel kernel, pi_uint32 arg_index,
                                  const pi_mem_obj_property *arg_properties,
                                  const pi_mem *arg_value) {
                                    S
  // Should plug in ye olde buffer here
  std::cerr << "[piextKernelSetArgMemObj] index: " << arg_index << "\n";
  if (arg_value == nullptr) {
    std::cerr << "Null arg!\n";
  }
  else {
    std::cerr << "MemObj Id: " << (*arg_value)->id << "\n";
    std::cerr << "MemObj Size: " << (*arg_value)->size << "\n";
  }

  const pi_mem_obj_property* properties = arg_properties;
  while (properties != nullptr) {
    std::cerr << "Mem Access: " << properties->mem_access << "\n";
    properties = reinterpret_cast<const pi_mem_obj_property*>(properties->pNext);
  }

  return PI_SUCCESS;
}

pi_result piextKernelSetArgSampler(pi_kernel kernel, pi_uint32 arg_index,
                                   const pi_sampler *arg_value) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextKernelCreateWithNativeHandle(pi_native_handle nativeHandle,
                                            pi_context, pi_program, bool,
                                            pi_kernel *piKernel) {
                                              S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextGetDeviceFunctionPointer(pi_device device, pi_program program,
                                        const char *func_name,
                                        pi_uint64 *function_pointer_ret) {
                                          S

return PI_ERROR_INVALID_OPERATION;
}

pi_result piContextCreate(const pi_context_properties *properties,
                          pi_uint32 num_devices, const pi_device *devices,
                          void (*pfn_notify)(const char *errinfo,
                                             const void *private_info,
                                             size_t cb, void *user_data1),
                          void *user_data, pi_context *retcontext) {
                            S                            
                            // TODO
 return PI_SUCCESS;
}

pi_result piextContextCreateWithNativeHandle(pi_native_handle nativeHandle,
                                             pi_uint32 num_devices,
                                             const pi_device *devices,
                                             bool ownNativeHandle,
                                             pi_context *piContext) {
                                              S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piContextGetInfo(pi_context context, pi_context_info paramName,
                           size_t paramValueSize, void *paramValue,
                           size_t *paramValueSizeRet) {
                            S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piMemBufferCreate(pi_context context, pi_mem_flags flags, size_t size,
                            void *host_ptr, pi_mem *ret_mem,
                            const pi_mem_properties *properties) {
                              S
                              // TODO
  std::cout << "[piMemBufferCreate] size " << size;
  auto mem = new _pi_mem;
  mem->id = blah::buffer_count;
  blah::buffer_count++;
  mem->size = size;
  // TODO add flags
  std::cerr << "Mem Id: " << mem->id << std::endl;
  *ret_mem = mem;
  return PI_SUCCESS;
}

pi_result piMemImageCreate(pi_context context, pi_mem_flags flags,
                           const pi_image_format *image_format,
                           const pi_image_desc *image_desc, void *host_ptr,
                           pi_mem *ret_mem) {
                            S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piMemBufferPartition(pi_mem buffer, pi_mem_flags flags,
                               pi_buffer_create_type buffer_create_type,
                               void *buffer_create_info, pi_mem *ret_mem) {
                                S

  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextMemCreateWithNativeHandle(pi_native_handle nativeHandle,
                                         pi_context context,
                                         bool ownNativeHandle, pi_mem *piMem) {
                                          S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextMemImageCreateWithNativeHandle(
    pi_native_handle nativeHandle, pi_context context, bool ownNativeHandle,
    const pi_image_format *ImageFormat, const pi_image_desc *ImageDesc,
    pi_mem *Img) {
      S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piclProgramCreateWithSource(pi_context context, pi_uint32 count,
                                      const char **strings,
                                      const size_t *lengths,
                                      pi_program *ret_program) {
                                        S

  return PI_ERROR_INVALID_OPERATION;
}

pi_result piProgramCreateWithBinary(
    pi_context context, pi_uint32 num_devices, const pi_device *device_list,
    const size_t *lengths, const unsigned char **binaries,
    size_t num_metadata_entries, const pi_device_binary_property *metadata,
    pi_int32 *binary_status, pi_program *ret_program) {
      S
 return PI_ERROR_INVALID_OPERATION;
}

pi_result piProgramLink(pi_context context, pi_uint32 num_devices,
                        const pi_device *device_list, const char *options,
                        pi_uint32 num_input_programs,
                        const pi_program *input_programs,
                        void (*pfn_notify)(pi_program program, void *user_data),
                        void *user_data, pi_program *ret_program) {
                          S

  return PI_ERROR_INVALID_OPERATION;
}

pi_result piKernelCreate(pi_program program, const char *kernel_name,
                         pi_kernel *ret_kernel) {
                          S
  // TODO
  // so we can build individual kernels out of a given program
  // will have to figure this out later
  // currently, simple.spv only has one kernel so the whole program becomes the kernel
  *ret_kernel = reinterpret_cast<pi_kernel>(program);
  return PI_SUCCESS;
}

pi_result piKernelGetGroupInfo(pi_kernel kernel, pi_device device,
                               pi_kernel_group_info param_name,
                               size_t param_value_size, void *param_value,
                               size_t *param_value_size_ret) {
                                S
                                // TODO

  std::cerr << "[piKernelGetGroupInfo] " << param_name << "\n";
  switch (param_name) {
    case PI_KERNEL_GROUP_INFO_COMPILE_WORK_GROUP_SIZE: {
      // should this be 0, 0, 0 or 1, 1, 1?
      size_t group_size[3] = {0, 0, 0};
      return blah::getInfoArray(3, param_value_size, param_value,
                          param_value_size_ret, group_size);
    }

    default: {
      std::cerr << "Unimplemented piKernelGetGroupInfo param\n";
      return PI_ERROR_INVALID_OPERATION;
    }
  }
}

pi_result piKernelGetSubGroupInfo(pi_kernel kernel, pi_device device,
                                  pi_kernel_sub_group_info param_name,
                                  size_t input_value_size,
                                  const void *input_value,
                                  size_t param_value_size, void *param_value,
                                  size_t *param_value_size_ret) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piEventCreate(pi_context context, pi_event *ret_event) {
  S

  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextEventCreateWithNativeHandle(pi_native_handle nativeHandle,
                                           pi_context context,
                                           bool ownNativeHandle,
                                           pi_event *piEvent) {
                                            S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piEnqueueMemBufferMap(pi_queue command_queue, pi_mem buffer,
                                pi_bool blocking_map, pi_map_flags map_flags,
                                size_t offset, size_t size,
                                pi_uint32 num_events_in_wait_list,
                                const pi_event *event_wait_list,
                                pi_event *event, void **ret_map) {
                                  S

  return PI_ERROR_INVALID_OPERATION;
}

//
// USM
//

/// Allocates host memory accessible by the device.
///
/// \param result_ptr contains the allocated memory
/// \param context is the pi_context
/// \param pi_usm_mem_properties are optional allocation properties
/// \param size_t is the size of the allocation
/// \param alignment is the desired alignment of the allocation
pi_result piextUSMHostAlloc(void **result_ptr, pi_context context,
                            pi_usm_mem_properties *properties, size_t size,
                            pi_uint32 alignment) {
                              S

  return PI_ERROR_INVALID_OPERATION;
}

/// Allocates device memory
///
/// \param result_ptr contains the allocated memory
/// \param context is the pi_context
/// \param device is the device the memory will be allocated on
/// \param pi_usm_mem_properties are optional allocation properties
/// \param size_t is the size of the allocation
/// \param alignment is the desired alignment of the allocation
pi_result piextUSMDeviceAlloc(void **result_ptr, pi_context context,
                              pi_device device,
                              pi_usm_mem_properties *properties, size_t size,
                              pi_uint32 alignment) {
                                S

  return PI_ERROR_INVALID_OPERATION;
}

/// Allocates memory accessible on both host and device
///
/// \param result_ptr contains the allocated memory
/// \param context is the pi_context
/// \param device is the device the memory will be allocated on
/// \param pi_usm_mem_properties are optional allocation properties
/// \param size_t is the size of the allocation
/// \param alignment is the desired alignment of the allocation
pi_result piextUSMSharedAlloc(void **result_ptr, pi_context context,
                              pi_device device,
                              pi_usm_mem_properties *properties, size_t size,
                              pi_uint32 alignment) {
                                S

  return PI_ERROR_INVALID_OPERATION;
}

/// Frees allocated USM memory in a blocking manner
///
/// \param context is the pi_context of the allocation
/// \param ptr is the memory to be freed
pi_result piextUSMFree(pi_context context, void *ptr) {
  S
  return PI_ERROR_INVALID_OPERATION;
}

/// Sets up pointer arguments for CL kernels. An extra indirection
/// is required due to CL argument conventions.
///
/// \param kernel is the kernel to be launched
/// \param arg_index is the index of the kernel argument
/// \param arg_size is the size in bytes of the argument (ignored in CL)
/// \param arg_value is the pointer argument
pi_result piextKernelSetArgPointer(pi_kernel kernel, pi_uint32 arg_index,
                                   size_t arg_size, const void *arg_value) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

/// USM Memset API
///
/// \param queue is the queue to submit to
/// \param ptr is the ptr to memset
/// \param value is value to set. It is interpreted as an 8-bit value and the
///        upper 24 bits are ignored
/// \param count is the size in bytes to memset
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
pi_result piextUSMEnqueueMemset(pi_queue queue, void *ptr, pi_int32 value,
                                size_t count, pi_uint32 num_events_in_waitlist,
                                const pi_event *events_waitlist,
                                pi_event *event) {
                                  S

  return PI_ERROR_INVALID_OPERATION;
}

/// USM Memcpy API
///
/// \param queue is the queue to submit to
/// \param blocking is whether this operation should block the host
/// \param src_ptr is the data to be copied
/// \param dst_ptr is the location the data will be copied
/// \param size is number of bytes to copy
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
pi_result piextUSMEnqueueMemcpy(pi_queue queue, pi_bool blocking, void *dst_ptr,
                                const void *src_ptr, size_t size,
                                pi_uint32 num_events_in_waitlist,
                                const pi_event *events_waitlist,
                                pi_event *event) {
                                  S

  return PI_ERROR_INVALID_OPERATION;
}

/// Hint to migrate memory to the device
///
/// \param queue is the queue to submit to
/// \param ptr points to the memory to migrate
/// \param size is the number of bytes to migrate
/// \param flags is a bitfield used to specify memory migration options
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
pi_result piextUSMEnqueuePrefetch(pi_queue queue, const void *ptr, size_t size,
                                  pi_usm_migration_flags flags,
                                  pi_uint32 num_events_in_waitlist,
                                  const pi_event *events_waitlist,
                                  pi_event *event) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

/// USM Memadvise API
///
/// \param queue is the queue to submit to
/// \param ptr is the data to be advised
/// \param length is the size in bytes of the meory to advise
/// \param advice is device specific advice
/// \param event is the event that represents this operation
// USM memadvise API to govern behavior of automatic migration mechanisms
pi_result piextUSMEnqueueMemAdvise(pi_queue queue, const void *ptr,
                                   size_t length, pi_mem_advice advice,
                                   pi_event *event) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

/// USM 2D Fill API
///
/// \param queue is the queue to submit to
/// \param ptr is the ptr to fill
/// \param pattern is a pointer with the bytes of the pattern to set
/// \param pattern_size is the size in bytes of the pattern
/// \param pitch is the total width of the destination memory including padding
/// \param width is width in bytes of each row to fill
/// \param height is height the columns to fill
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
__SYCL_EXPORT pi_result piextUSMEnqueueFill2D(pi_queue queue, void *ptr,
                                              size_t pitch, size_t pattern_size,
                                              const void *pattern, size_t width,
                                              size_t height,
                                              pi_uint32 num_events_in_waitlist,
                                              const pi_event *events_waitlist,
                                              pi_event *event) {
                                                S
  std::ignore = queue;
  std::ignore = ptr;
  std::ignore = pitch;
  std::ignore = pattern_size;
  std::ignore = pattern;
  std::ignore = width;
  std::ignore = height;
  std::ignore = num_events_in_waitlist;
  std::ignore = events_waitlist;
  std::ignore = event;
  return PI_ERROR_INVALID_OPERATION;
}

/// USM 2D Memset API
///
/// \param queue is the queue to submit to
/// \param ptr is the ptr to memset
/// \param value contains the byte to set with
/// \param pitch is the total width of the destination memory including padding
/// \param width is width in bytes of each row to memset
/// \param height is height the columns to memset
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
__SYCL_EXPORT pi_result piextUSMEnqueueMemset2D(
    pi_queue queue, void *ptr, size_t pitch, int value, size_t width,
    size_t height, pi_uint32 num_events_in_waitlist,
    const pi_event *events_waitlist, pi_event *event) {
      S
  std::ignore = queue;
  std::ignore = ptr;
  std::ignore = pitch;
  std::ignore = value;
  std::ignore = width;
  std::ignore = height;
  std::ignore = num_events_in_waitlist;
  std::ignore = events_waitlist;
  std::ignore = event;
  return PI_ERROR_INVALID_OPERATION;
}

/// USM 2D Memcpy API
///
/// \param queue is the queue to submit to
/// \param blocking is whether this operation should block the host
/// \param dst_ptr is the location the data will be copied
/// \param dst_pitch is the total width of the destination memory including
/// padding
/// \param src_ptr is the data to be copied
/// \param dst_pitch is the total width of the source memory including padding
/// \param width is width in bytes of each row to be copied
/// \param height is height the columns to be copied
/// \param num_events_in_waitlist is the number of events to wait on
/// \param events_waitlist is an array of events to wait on
/// \param event is the event that represents this operation
__SYCL_EXPORT pi_result piextUSMEnqueueMemcpy2D(
    pi_queue queue, pi_bool blocking, void *dst_ptr, size_t dst_pitch,
    const void *src_ptr, size_t src_pitch, size_t width, size_t height,
    pi_uint32 num_events_in_waitlist, const pi_event *events_waitlist,
    pi_event *event) {
      S
  std::ignore = queue;
  std::ignore = blocking;
  std::ignore = dst_ptr;
  std::ignore = dst_pitch;
  std::ignore = src_ptr;
  std::ignore = src_pitch;
  std::ignore = width;
  std::ignore = height;
  std::ignore = num_events_in_waitlist;
  std::ignore = events_waitlist;
  std::ignore = event;
  return PI_ERROR_INVALID_OPERATION;
}

/// API to query information about USM allocated pointers
/// Valid Queries:
///   PI_MEM_ALLOC_TYPE returns host/device/shared pi_host_usm value
///   PI_MEM_ALLOC_BASE_PTR returns the base ptr of an allocation if
///                         the queried pointer fell inside an allocation.
///                         Result must fit in void *
///   PI_MEM_ALLOC_SIZE returns how big the queried pointer's
///                     allocation is in bytes. Result is a size_t.
///   PI_MEM_ALLOC_DEVICE returns the pi_device this was allocated against
///
/// \param context is the pi_context
/// \param ptr is the pointer to query
/// \param param_name is the type of query to perform
/// \param param_value_size is the size of the result in bytes
/// \param param_value is the result
/// \param param_value_ret is how many bytes were written
pi_result piextUSMGetMemAllocInfo(pi_context context, const void *ptr,
                                  pi_mem_alloc_info param_name,
                                  size_t param_value_size, void *param_value,
                                  size_t *param_value_size_ret) {
                                    S

  return PI_ERROR_INVALID_OPERATION;
}

/// API for writing data from host to a device global variable.
///
/// \param queue is the queue
/// \param program is the program containing the device global variable
/// \param name is the unique identifier for the device global variable
/// \param blocking_write is true if the write should block
/// \param count is the number of bytes to copy
/// \param offset is the byte offset into the device global variable to start
/// copying
/// \param src is a pointer to where the data must be copied from
/// \param num_events_in_wait_list is a number of events in the wait list
/// \param event_wait_list is the wait list
/// \param event is the resulting event
pi_result piextEnqueueDeviceGlobalVariableWrite(
    pi_queue queue, pi_program program, const char *name,
    pi_bool blocking_write, size_t count, size_t offset, const void *src,
    pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list,
    pi_event *event) {
      S
  return PI_ERROR_INVALID_OPERATION;
}

/// API reading data from a device global variable to host.
///
/// \param queue is the queue
/// \param program is the program containing the device global variable
/// \param name is the unique identifier for the device global variable
/// \param blocking_read is true if the read should block
/// \param count is the number of bytes to copy
/// \param offset is the byte offset into the device global variable to start
/// copying
/// \param dst is a pointer to where the data must be copied to
/// \param num_events_in_wait_list is a number of events in the wait list
/// \param event_wait_list is the wait list
/// \param event is the resulting event
pi_result piextEnqueueDeviceGlobalVariableRead(
    pi_queue queue, pi_program program, const char *name, pi_bool blocking_read,
    size_t count, size_t offset, void *dst, pi_uint32 num_events_in_wait_list,
    const pi_event *event_wait_list, pi_event *event) {
      S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextEnqueueReadHostPipe(pi_queue queue, pi_program program,
                                   const char *pipe_symbol, pi_bool blocking,
                                   void *ptr, size_t size,
                                   pi_uint32 num_events_in_waitlist,
                                   const pi_event *events_waitlist,
                                   pi_event *event) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextEnqueueWriteHostPipe(pi_queue queue, pi_program program,
                                    const char *pipe_symbol, pi_bool blocking,
                                    void *ptr, size_t size,
                                    pi_uint32 num_events_in_waitlist,
                                    const pi_event *events_waitlist,
                                    pi_event *event) {
                                      S
  return PI_ERROR_INVALID_OPERATION;
}

/// API to set attributes controlling kernel execution
///
/// \param kernel is the pi kernel to execute
/// \param param_name is a pi_kernel_exec_info value that specifies the info
///        passed to the kernel
/// \param param_value_size is the size of the value in bytes
/// \param param_value is a pointer to the value to set for the kernel
///
/// If param_name is PI_USM_INDIRECT_ACCESS, the value will be a ptr to
///    the pi_bool value PI_TRUE
/// If param_name is PI_USM_PTRS, the value will be an array of ptrs
pi_result piKernelSetExecInfo(pi_kernel kernel, pi_kernel_exec_info param_name,
                              size_t param_value_size,
                              const void *param_value) {
                                S
  // TODO
  // We don't really care so just pass through
  return PI_SUCCESS;
}

pi_result piextProgramSetSpecializationConstant(pi_program prog,
                                                pi_uint32 spec_id,
                                                size_t spec_size,
                                                const void *spec_value) {
                                                  S
  return PI_ERROR_INVALID_OPERATION;
}

/// Common API for getting the native handle of a PI object
///
/// \param piObj is the pi object to get the native handle of
/// \param nativeHandle is a pointer to be set to the native handle
///
/// PI_SUCCESS
static pi_result piextGetNativeHandle(void *piObj,
                                      pi_native_handle *nativeHandle) {
                                        S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextPlatformGetNativeHandle(pi_platform platform,
                                       pi_native_handle *nativeHandle) {
                                        S
  return piextGetNativeHandle(platform, nativeHandle);
}

pi_result piextDeviceGetNativeHandle(pi_device device,
                                     pi_native_handle *nativeHandle) {
                                      S
  return piextGetNativeHandle(device, nativeHandle);
}

pi_result piextContextGetNativeHandle(pi_context context,
                                      pi_native_handle *nativeHandle) {
                                        S
  return piextGetNativeHandle(context, nativeHandle);
}

pi_result piextQueueGetNativeHandle(pi_queue queue,
                                    pi_native_handle *nativeHandle,
                                    int32_t *nativeHandleDesc) {
                                      S
  *nativeHandleDesc = 0;
  return piextGetNativeHandle(queue, nativeHandle);
}

pi_result piextMemGetNativeHandle(pi_mem mem, pi_native_handle *nativeHandle) {
  S
  return piextGetNativeHandle(mem, nativeHandle);
}

pi_result piextProgramGetNativeHandle(pi_program program,
                                      pi_native_handle *nativeHandle) {
                                        S
  return piextGetNativeHandle(program, nativeHandle);
}

pi_result piextKernelGetNativeHandle(pi_kernel kernel,
                                     pi_native_handle *nativeHandle) {
                                      S
  return piextGetNativeHandle(kernel, nativeHandle);
}

// command-buffer extension
pi_result piextCommandBufferCreate(pi_context context, pi_device device,
                                   const pi_ext_command_buffer_desc *desc,
                                   pi_ext_command_buffer *ret_command_buffer) {
                                    S
  (void)context;
  (void)device;
  (void)desc;
  (void)ret_command_buffer;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferRetain(pi_ext_command_buffer command_buffer) {
  S
  (void)command_buffer;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferRelease(pi_ext_command_buffer command_buffer) {
  S
  (void)command_buffer;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferFinalize(pi_ext_command_buffer command_buffer) {
  S
  (void)command_buffer;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferNDRangeKernel(
    pi_ext_command_buffer command_buffer, pi_kernel kernel, pi_uint32 work_dim,
    const size_t *global_work_offset, const size_t *global_work_size,
    const size_t *local_work_size, pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)kernel;
  (void)work_dim;
  (void)global_work_offset;
  (void)global_work_size;
  (void)local_work_size;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result
piextCommandBufferMemcpyUSM(pi_ext_command_buffer command_buffer, void *dst_ptr,
                            const void *src_ptr, size_t size,
                            pi_uint32 num_sync_points_in_wait_list,
                            const pi_ext_sync_point *sync_point_wait_list,
                            pi_ext_sync_point *sync_point) {
                              S
  (void)command_buffer;
  (void)dst_ptr;
  (void)src_ptr;
  (void)size;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferCopy(
    pi_ext_command_buffer command_buffer, pi_mem src_buffer, pi_mem dst_buffer,
    size_t src_offset, size_t dst_offset, size_t size,
    pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)src_buffer;
  (void)dst_buffer;
  (void)src_offset;
  (void)dst_offset;
  (void)size;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferCopyRect(
    pi_ext_command_buffer command_buffer, pi_mem src_buffer, pi_mem dst_buffer,
    pi_buff_rect_offset src_origin, pi_buff_rect_offset dst_origin,
    pi_buff_rect_region region, size_t src_row_pitch, size_t src_slice_pitch,
    size_t dst_row_pitch, size_t dst_slice_pitch,
    pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)src_buffer;
  (void)dst_buffer;
  (void)src_origin;
  (void)dst_origin;
  (void)region;
  (void)src_row_pitch;
  (void)src_slice_pitch;
  (void)dst_row_pitch;
  (void)dst_slice_pitch;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferRead(
    pi_ext_command_buffer command_buffer, pi_mem buffer, size_t offset,
    size_t size, void *dst, pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)buffer;
  (void)offset;
  (void)size;
  (void)dst;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferReadRect(
    pi_ext_command_buffer command_buffer, pi_mem buffer,
    pi_buff_rect_offset buffer_offset, pi_buff_rect_offset host_offset,
    pi_buff_rect_region region, size_t buffer_row_pitch,
    size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch,
    void *ptr, pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)buffer;
  (void)buffer_offset;
  (void)host_offset;
  (void)region;
  (void)buffer_row_pitch;
  (void)buffer_slice_pitch;
  (void)host_row_pitch;
  (void)host_slice_pitch;
  (void)ptr;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferWrite(
    pi_ext_command_buffer command_buffer, pi_mem buffer, size_t offset,
    size_t size, const void *ptr, pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)buffer;
  (void)offset;
  (void)size;
  (void)ptr;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextCommandBufferMemBufferWriteRect(
    pi_ext_command_buffer command_buffer, pi_mem buffer,
    pi_buff_rect_offset buffer_offset, pi_buff_rect_offset host_offset,
    pi_buff_rect_region region, size_t buffer_row_pitch,
    size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch,
    const void *ptr, pi_uint32 num_sync_points_in_wait_list,
    const pi_ext_sync_point *sync_point_wait_list,
    pi_ext_sync_point *sync_point) {
      S
  (void)command_buffer;
  (void)buffer;
  (void)buffer_offset;
  (void)host_offset;
  (void)region;
  (void)buffer_row_pitch;
  (void)buffer_slice_pitch;
  (void)host_row_pitch;
  (void)host_slice_pitch;
  (void)ptr;
  (void)num_sync_points_in_wait_list;
  (void)sync_point_wait_list;
  (void)sync_point;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piextEnqueueCommandBuffer(pi_ext_command_buffer command_buffer,
                                    pi_queue queue,
                                    pi_uint32 num_events_in_wait_list,
                                    const pi_event *event_wait_list,
                                    pi_event *event) {
                                      S
  (void)command_buffer;
  (void)queue;
  (void)num_events_in_wait_list;
  (void)event_wait_list;
  (void)event;

  // Not implemented
  return PI_ERROR_INVALID_OPERATION;
}

// This API is called by Sycl RT to notify the end of the plugin lifetime.
// Windows: dynamically loaded plugins might have been unloaded already
// when this is called. Sycl RT holds onto the PI plugin so it can be
// called safely. But this is not transitive. If the PI plugin in turn
// dynamically loaded a different DLL, that may have been unloaded.
// TODO: add a global variable lifetime management code here (see
// pi_level_zero.cpp for reference).
pi_result piTearDown(void *PluginParameter) {
  S
  return PI_SUCCESS;
}

pi_result piGetDeviceAndHostTimer(pi_device Device, uint64_t *DeviceTime,
                                  uint64_t *HostTime) {
                                    S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piEventGetInfo(pi_event event, pi_event_info param_name,
                         size_t param_value_size, void *param_value,
                         size_t *param_value_size_ret) {
                          S
  return PI_ERROR_INVALID_OPERATION;
}

// Extra untranslated APIs...
pi_result piDevicePartition(pi_device device, const pi_device_partition_property *properties, pi_uint32 num_devices, pi_device *out_devices, pi_uint32 *out_num_devices) {
  S
  return PI_ERROR_INVALID_OPERATION;
}

pi_result piDeviceRetain(pi_device device) {
  S
return PI_SUCCESS;
}

pi_result piDeviceRelease(pi_device device) {
  S
  
return PI_SUCCESS;
}
pi_result piContextRetain(pi_context context) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piContextRelease(pi_context context) {
  S
return PI_SUCCESS;
}
pi_result piQueueFinish(pi_queue command_queue) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piQueueFlush(pi_queue command_queue) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piQueueRetain(pi_queue command_queue) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piQueueRelease(pi_queue command_queue) {
  S
return PI_SUCCESS;
}
pi_result piMemGetInfo(pi_mem mem, pi_mem_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piMemImageGetInfo(pi_mem image, pi_image_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piMemRetain(pi_mem mem) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piMemRelease(pi_mem mem) {
  S
  delete mem;
return PI_SUCCESS;
}
pi_result piProgramGetInfo(pi_program program, pi_program_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piProgramCompile(pi_program program, pi_uint32 num_devices, const pi_device *device_list, const char *options, pi_uint32 num_input_headers, const pi_program *input_headers, const char **header_include_names, void (*pfn_notify)(pi_program program, void *user_data), void *user_data) {
  S
return PI_ERROR_INVALID_OPERATION;
}


pi_result piProgramBuild(pi_program program, pi_uint32 num_devices, const pi_device *device_list, const char *options, void (*pfn_notify)(pi_program program, void *user_data), void *user_data) {
  S
  // TODO
  // we don't actually need to do anything since the execution
  // engine will just interpret spirv
  // pi_program can remain as is
return PI_SUCCESS;
}

pi_result piProgramGetBuildInfo(pi_program program, pi_device device, _pi_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piProgramRetain(pi_program program) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piProgramRelease(pi_program program) {
  S
return PI_SUCCESS;
}

pi_result piKernelSetArg(pi_kernel kernel, pi_uint32 arg_index, size_t arg_size, const void *arg_value) {
  S
  // TODO
  std::cerr << "[piKernelSetArg] index: " << arg_index << " size: " << arg_size << "\n";
  std::cerr << "Arg val: " << arg_value << "\n";
  return PI_SUCCESS;
}

pi_result piKernelGetInfo(pi_kernel kernel, pi_kernel_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piKernelRetain(pi_kernel kernel) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piKernelRelease(pi_kernel kernel) {
  S
return PI_SUCCESS;
}
pi_result piEventGetProfilingInfo(pi_event event, pi_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEventsWait(pi_uint32 num_events, const pi_event *event_list) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEventSetCallback(pi_event event, pi_int32 command_exec_callback_type, void (*pfn_notify)(pi_event event, pi_int32 event_command_status, void *user_data), void *user_data) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEventSetStatus(pi_event event, pi_int32 execution_status) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEventRetain(pi_event event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEventRelease(pi_event event) {
  S
return PI_ERROR_INVALID_OPERATION;
}

pi_result piSamplerGetInfo(pi_sampler sampler, pi_sampler_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piSamplerRetain(pi_sampler sampler) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piSamplerRelease(pi_sampler sampler) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueKernelLaunch(pi_queue queue, pi_kernel kernel, pi_uint32 work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
  // TODO
return PI_SUCCESS;
}
pi_result piEnqueueNativeKernel(pi_queue queue, void (*user_func)(void *), void *args, size_t cb_args, pi_uint32 num_mem_objects, const pi_mem *mem_list, const void **args_mem_loc, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueEventsWait(pi_queue command_queue, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueEventsWaitWithBarrier(pi_queue command_queue, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}

pi_result piEnqueueMemBufferRead(pi_queue queue, pi_mem buffer, pi_bool blocking_read, size_t offset, size_t size, void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
  std::cerr << "Buffer ID: " << buffer->id << std::endl;
  std::cerr << "Buffer Size: " << buffer->size << std::endl;
  std::cerr << "Ptr: " << ptr << std::endl;
  std::cerr << "Blocking: " << blocking_read << std::endl;
  std::cerr << "Offset: " << offset << std::endl;
  std::cerr << "Size: " << size << std::endl;
  auto items = reinterpret_cast<int*>(ptr);
  for (int i = 0; i < 8; i++) {
    items[i] = i;
  }
  return PI_SUCCESS;
}

pi_result piEnqueueMemBufferReadRect(pi_queue command_queue, pi_mem buffer, pi_bool blocking_read, pi_buff_rect_offset buffer_offset, pi_buff_rect_offset host_offset, pi_buff_rect_region region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemBufferWrite(pi_queue command_queue, pi_mem buffer, pi_bool blocking_write, size_t offset, size_t size, const void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemBufferWriteRect(pi_queue command_queue, pi_mem buffer, pi_bool blocking_write, pi_buff_rect_offset buffer_offset, pi_buff_rect_offset host_offset, pi_buff_rect_region region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, const void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemBufferCopy(pi_queue command_queue, pi_mem src_buffer, pi_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemBufferCopyRect(pi_queue command_queue, pi_mem src_buffer, pi_mem dst_buffer, pi_buff_rect_offset src_origin, pi_buff_rect_offset dst_origin, pi_buff_rect_region region, size_t src_row_pitch, size_t src_slice_pitch, size_t dst_row_pitch, size_t dst_slice_pitch, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemBufferFill(pi_queue command_queue, pi_mem buffer, const void *pattern, size_t pattern_size, size_t offset, size_t size, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemImageRead(pi_queue command_queue, pi_mem image, pi_bool blocking_read, pi_image_offset origin, pi_image_region region, size_t row_pitch, size_t slice_pitch, void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemImageWrite(pi_queue command_queue, pi_mem image, pi_bool blocking_write, pi_image_offset origin, pi_image_region region, size_t input_row_pitch, size_t input_slice_pitch, const void *ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemImageCopy(pi_queue command_queue, pi_mem src_image, pi_mem dst_image, pi_image_offset src_origin, pi_image_offset dst_origin, pi_image_region region, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemImageFill(pi_queue command_queue, pi_mem image, const void *fill_color, const size_t *origin, const size_t *region, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}
pi_result piEnqueueMemUnmap(pi_queue command_queue, pi_mem memobj, void *mapped_ptr, pi_uint32 num_events_in_wait_list, const pi_event *event_wait_list, pi_event *event) {
  S
return PI_ERROR_INVALID_OPERATION;
}


pi_result piPluginInit(pi_plugin *PluginInit) {
  S

#define _PI_SCYTHE(pi_api, scythe_api)                                                \
  (PluginInit->PiFunctionTable).pi_api = (decltype(&::pi_api))(&scythe_api);

  // Platform
  _PI_SCYTHE(piPlatformsGet, piPlatformsGet)
  _PI_SCYTHE(piPlatformGetInfo, piPlatformGetInfo)
  _PI_SCYTHE(piextPlatformGetNativeHandle, piextPlatformGetNativeHandle)
  _PI_SCYTHE(piextPlatformCreateWithNativeHandle,
         piextPlatformCreateWithNativeHandle)
  // Device
  _PI_SCYTHE(piDevicesGet, piDevicesGet)
  _PI_SCYTHE(piDeviceGetInfo, piDeviceGetInfo)
  _PI_SCYTHE(piDevicePartition, piDevicePartition)
  _PI_SCYTHE(piDeviceRetain, piDeviceRetain)
  _PI_SCYTHE(piDeviceRelease, piDeviceRelease)
  _PI_SCYTHE(piextDeviceSelectBinary, piextDeviceSelectBinary)
  _PI_SCYTHE(piextGetDeviceFunctionPointer, piextGetDeviceFunctionPointer)
  _PI_SCYTHE(piextDeviceGetNativeHandle, piextDeviceGetNativeHandle)
  _PI_SCYTHE(piextDeviceCreateWithNativeHandle, piextDeviceCreateWithNativeHandle)
  // Context
  _PI_SCYTHE(piContextCreate, piContextCreate)
  _PI_SCYTHE(piContextGetInfo, piContextGetInfo)
  _PI_SCYTHE(piContextRetain, piContextRetain)
  _PI_SCYTHE(piContextRelease, piContextRelease)
  _PI_SCYTHE(piextContextGetNativeHandle, piextContextGetNativeHandle)
  _PI_SCYTHE(piextContextCreateWithNativeHandle, piextContextCreateWithNativeHandle)
  // Queue
  _PI_SCYTHE(piQueueCreate, piQueueCreate)
  _PI_SCYTHE(piextQueueCreate, piextQueueCreate)
  _PI_SCYTHE(piQueueGetInfo, piQueueGetInfo)
  _PI_SCYTHE(piQueueFinish, piQueueFinish)
  _PI_SCYTHE(piQueueFlush, piQueueFlush)
  _PI_SCYTHE(piQueueRetain, piQueueRetain)
  _PI_SCYTHE(piQueueRelease, piQueueRelease)
  _PI_SCYTHE(piextQueueGetNativeHandle, piextQueueGetNativeHandle)
  _PI_SCYTHE(piextQueueCreateWithNativeHandle, piextQueueCreateWithNativeHandle)
  // Memory
  _PI_SCYTHE(piMemBufferCreate, piMemBufferCreate)
  _PI_SCYTHE(piMemImageCreate, piMemImageCreate)
  _PI_SCYTHE(piMemGetInfo, piMemGetInfo)
  _PI_SCYTHE(piMemImageGetInfo, piMemImageGetInfo)
  _PI_SCYTHE(piMemRetain, piMemRetain)
  _PI_SCYTHE(piMemRelease, piMemRelease)
  _PI_SCYTHE(piMemBufferPartition, piMemBufferPartition)
  _PI_SCYTHE(piextMemGetNativeHandle, piextMemGetNativeHandle)
  _PI_SCYTHE(piextMemCreateWithNativeHandle, piextMemCreateWithNativeHandle)
  // Program
  _PI_SCYTHE(piProgramCreate, piProgramCreate)
  _PI_SCYTHE(piclProgramCreateWithSource, piclProgramCreateWithSource)
  _PI_SCYTHE(piProgramCreateWithBinary, piProgramCreateWithBinary)
  _PI_SCYTHE(piProgramGetInfo, piProgramGetInfo)
  _PI_SCYTHE(piProgramCompile, piProgramCompile)
  _PI_SCYTHE(piProgramBuild, piProgramBuild)
  _PI_SCYTHE(piProgramLink, piProgramLink)
  _PI_SCYTHE(piProgramGetBuildInfo, piProgramGetBuildInfo)
  _PI_SCYTHE(piProgramRetain, piProgramRetain)
  _PI_SCYTHE(piProgramRelease, piProgramRelease)
  _PI_SCYTHE(piextProgramSetSpecializationConstant,
         piextProgramSetSpecializationConstant)
  _PI_SCYTHE(piextProgramGetNativeHandle, piextProgramGetNativeHandle)
  _PI_SCYTHE(piextProgramCreateWithNativeHandle, piextProgramCreateWithNativeHandle)
  // Kernel
  _PI_SCYTHE(piKernelCreate, piKernelCreate)
  _PI_SCYTHE(piKernelSetArg, piKernelSetArg)
  _PI_SCYTHE(piKernelGetInfo, piKernelGetInfo)
  _PI_SCYTHE(piKernelGetGroupInfo, piKernelGetGroupInfo)
  _PI_SCYTHE(piKernelGetSubGroupInfo, piKernelGetSubGroupInfo)
  _PI_SCYTHE(piKernelRetain, piKernelRetain)
  _PI_SCYTHE(piKernelRelease, piKernelRelease)
  _PI_SCYTHE(piKernelSetExecInfo, piKernelSetExecInfo)
  _PI_SCYTHE(piextKernelSetArgPointer, piextKernelSetArgPointer)
  _PI_SCYTHE(piextKernelCreateWithNativeHandle, piextKernelCreateWithNativeHandle)
  _PI_SCYTHE(piextKernelGetNativeHandle, piextKernelGetNativeHandle)
  // Event
  _PI_SCYTHE(piEventCreate, piEventCreate)
  _PI_SCYTHE(piEventGetInfo, piEventGetInfo)
  _PI_SCYTHE(piEventGetProfilingInfo, piEventGetProfilingInfo)
  _PI_SCYTHE(piEventsWait, piEventsWait)
  _PI_SCYTHE(piEventSetCallback, piEventSetCallback)
  _PI_SCYTHE(piEventSetStatus, piEventSetStatus)
  _PI_SCYTHE(piEventRetain, piEventRetain)
  _PI_SCYTHE(piEventRelease, piEventRelease)
  _PI_SCYTHE(piextEventGetNativeHandle, piextGetNativeHandle)
  _PI_SCYTHE(piextEventCreateWithNativeHandle, piextEventCreateWithNativeHandle)
  // Sampler


  _PI_SCYTHE(piSamplerCreate, piSamplerCreate)
  _PI_SCYTHE(piSamplerGetInfo, piSamplerGetInfo)
  _PI_SCYTHE(piSamplerRetain, piSamplerRetain)
  _PI_SCYTHE(piSamplerRelease, piSamplerRelease)
  // Queue commands
  _PI_SCYTHE(piEnqueueKernelLaunch, piEnqueueKernelLaunch)
  _PI_SCYTHE(piEnqueueNativeKernel, piEnqueueNativeKernel)
  _PI_SCYTHE(piEnqueueEventsWait, piEnqueueEventsWait)
  _PI_SCYTHE(piEnqueueEventsWaitWithBarrier, piEnqueueEventsWaitWithBarrier)
  _PI_SCYTHE(piEnqueueMemBufferRead, piEnqueueMemBufferRead)
  _PI_SCYTHE(piEnqueueMemBufferReadRect, piEnqueueMemBufferReadRect)
  _PI_SCYTHE(piEnqueueMemBufferWrite, piEnqueueMemBufferWrite)
  _PI_SCYTHE(piEnqueueMemBufferWriteRect, piEnqueueMemBufferWriteRect)
  _PI_SCYTHE(piEnqueueMemBufferCopy, piEnqueueMemBufferCopy)
  _PI_SCYTHE(piEnqueueMemBufferCopyRect, piEnqueueMemBufferCopyRect)
  _PI_SCYTHE(piEnqueueMemBufferFill, piEnqueueMemBufferFill)
  _PI_SCYTHE(piEnqueueMemImageRead, piEnqueueMemImageRead)
  _PI_SCYTHE(piEnqueueMemImageWrite, piEnqueueMemImageWrite)
  _PI_SCYTHE(piEnqueueMemImageCopy, piEnqueueMemImageCopy)
  _PI_SCYTHE(piEnqueueMemImageFill, piEnqueueMemImageFill)
  _PI_SCYTHE(piEnqueueMemBufferMap, piEnqueueMemBufferMap)
  _PI_SCYTHE(piEnqueueMemUnmap, piEnqueueMemUnmap)
  // USM
  _PI_SCYTHE(piextUSMHostAlloc, piextUSMHostAlloc)
  _PI_SCYTHE(piextUSMDeviceAlloc, piextUSMDeviceAlloc)
  _PI_SCYTHE(piextUSMSharedAlloc, piextUSMSharedAlloc)
  _PI_SCYTHE(piextUSMFree, piextUSMFree)
  _PI_SCYTHE(piextUSMEnqueueMemset, piextUSMEnqueueMemset)
  _PI_SCYTHE(piextUSMEnqueueMemcpy, piextUSMEnqueueMemcpy)
  _PI_SCYTHE(piextUSMEnqueuePrefetch, piextUSMEnqueuePrefetch)
  _PI_SCYTHE(piextUSMEnqueueMemAdvise, piextUSMEnqueueMemAdvise)
  _PI_SCYTHE(piextUSMEnqueueFill2D, piextUSMEnqueueFill2D)
  _PI_SCYTHE(piextUSMEnqueueMemset2D, piextUSMEnqueueMemset2D)
  _PI_SCYTHE(piextUSMEnqueueMemcpy2D, piextUSMEnqueueMemcpy2D)
  _PI_SCYTHE(piextUSMGetMemAllocInfo, piextUSMGetMemAllocInfo)
  // Device global variable
  _PI_SCYTHE(piextEnqueueDeviceGlobalVariableWrite,
         piextEnqueueDeviceGlobalVariableWrite)
  _PI_SCYTHE(piextEnqueueDeviceGlobalVariableRead,
         piextEnqueueDeviceGlobalVariableRead)
  // Host Pipe
  _PI_SCYTHE(piextEnqueueReadHostPipe, piextEnqueueReadHostPipe)
  _PI_SCYTHE(piextEnqueueWriteHostPipe, piextEnqueueWriteHostPipe)

  // command-buffer
  _PI_SCYTHE(piextCommandBufferCreate, piextCommandBufferCreate)
  _PI_SCYTHE(piextCommandBufferRetain, piextCommandBufferRetain)
  _PI_SCYTHE(piextCommandBufferRelease, piextCommandBufferRelease)
  _PI_SCYTHE(piextCommandBufferNDRangeKernel, piextCommandBufferNDRangeKernel)
  _PI_SCYTHE(piextCommandBufferMemcpyUSM, piextCommandBufferMemcpyUSM)
  _PI_SCYTHE(piextCommandBufferMemBufferCopy, piextCommandBufferMemBufferCopy)
  _PI_SCYTHE(piextCommandBufferMemBufferCopyRect,
         piextCommandBufferMemBufferCopyRect)
  _PI_SCYTHE(piextEnqueueCommandBuffer, piextEnqueueCommandBuffer)

  _PI_SCYTHE(piextKernelSetArgMemObj, piextKernelSetArgMemObj)
  _PI_SCYTHE(piextKernelSetArgSampler, piextKernelSetArgSampler)
  _PI_SCYTHE(piPluginGetLastError, piPluginGetLastError)
  _PI_SCYTHE(piTearDown, piTearDown)
  _PI_SCYTHE(piGetDeviceAndHostTimer, piGetDeviceAndHostTimer)
  _PI_SCYTHE(piPluginGetBackendOption, piPluginGetBackendOption)

#undef _PI_SCYTHE

  return PI_SUCCESS;
}

#ifdef _WIN32
#define __SYCL_PLUGIN_DLL_NAME "pi_opencl.dll"
#include "../common_win_pi_trace/common_win_pi_trace.hpp"
#undef __SYCL_PLUGIN_DLL_NAME
#endif

} // end extern 'C'
