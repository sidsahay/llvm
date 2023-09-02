// License info?
// Scythe device selctors
// Adapted from ext/intel/fpga_device_selector.hpp

#pragma once

#include <sycl/device.hpp>
#include <sycl/device_selector.hpp>

#include <string>

namespace sycl {
__SYCL_INLINE_VER_NAMESPACE(_V1) {

// Forward declaration
class platform;

namespace ext::scythe {

namespace detail {
// was string_view really needed?
inline int selectDeviceByPlatform(std::string required_platform_name,
                                  const device &device) {
  if (device.get_platform().get_info<sycl::info::platform::name>() ==
      required_platform_name)
    return 10000;
  return -1;
}

} // namespace detail


static constexpr auto SCYTHE_PLATFORM_NAME =
    "Scythe Platform";
static constexpr auto XRD_PLATFORM_NAME =
    "Crossroads Platform";

inline int scythe_selector_v(const device &device) {
  return detail::selectDeviceByPlatform(SCYTHE_PLATFORM_NAME, device);
}

inline int xrd_selector_v(const device &device) {
  return detail::selectDeviceByPlatform(XRD_PLATFORM_NAME, device);
}

} // namespace ext::scythe

} // __SYCL_INLINE_VER_NAMESPACE(_V1)
} // namespace sycl
