// License info?
// Scythe plugin - interface to Scythe and Crossroads devices

#ifndef PI_SCYTHE_HPP
#define PI_SCYTHE_HPP

#include <climits>
#include <regex>
#include <string>
#include <variant>

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
  std::vector<_pi_mem*> memories;
  std::map<size_t, std::vector<uint8_t>> memory_area;
  std::map<spire::SpirvId, spire::SpirvValue> values;

  void allocate_memories() {
    for (const auto& mem : memories) {
      memory_area[mem->mem.id].resize(mem->mem.size, 0);
    }
  }
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
  std::vector<uint8_t> layout;
  uint32_t past_block;
  uint32_t current_block;

  _pi_kernel(_pi_program* program) 
    : kernel(program->program.kernels.begin()->second), program(program), refcount(1) {}

  int inc_ref() {
    return ++refcount;
  }

  int dec_ref() {
    return --refcount;
  }

  void bind_membuffer_arg(size_t arg_idx, int mem_buffer_id) {
    kernel.function.params[arg_idx].mem_buffer_id = mem_buffer_id;
  };
};

using namespace spire;
using namespace spire::impl;

void run(Label& label, _pi_kernel* kernel, size_t& pc) {
  std::cerr << "Crossed label %" << label.result_id << std::endl;
  kernel->past_block = kernel->current_block;
  kernel->current_block = label.result_id;
  pc++;
}

void run(FunctionCall& fcall, _pi_kernel* kernel, size_t& pc) {
  std::cerr << "Ignoring function call %" << fcall.function << std::endl;
  pc++;
}

SpirvValue& get_value(_pi_kernel* kernel, SpirvId id) {
  return kernel->program->context->values[id];
}

void set_value(_pi_kernel* kernel, SpirvId type_id, SpirvId id, uint64_t direct, std::vector<uint32_t> variable) {
  auto& values = kernel->program->context->values;
  values[id] = {type_id, id, direct, variable};
}

#define is std::holds_alternative

void run(Bitcast& bcast, _pi_kernel* kernel, size_t& pc) {
  auto& types = kernel->program->program.types;
  auto& dest_type = types[bcast.result_type];

  // bitcast can only handle pointer destinations
  if (!is<TypePointer>(dest_type)) {
    std::cerr << "Bitcast called with non-pointer destination %" << bcast.result_type << std::endl;
    std::terminate();
  }

  SpirvValue& source = get_value(kernel, bcast.operand);
  auto& source_type = kernel->program->program.types[source.type_id];
  
  // only handle pointer sources
  if (is<TypePointer>(source_type)) {
    // just change the pointer type and copy over the direct value
    set_value(kernel, bcast.result_type, bcast.result_id, source.direct, {});  
  }
  else {
    std::cerr << "Bitcast called with non-pointer source %" << source.type_id << std::endl;
    std::terminate();
  }
  
  std::cerr << "Processed bitcast from %" << source.type_id << " to %" << bcast.result_type << std::endl;
  pc++;
}

void run(Load& load, _pi_kernel* kernel, size_t& pc) {
  auto& types = kernel->program->program.types;
  auto& dest_type = types[load.result_type];

  // we only do int loads for now
  if (!is<TypeInt>(dest_type)) {
    std::cerr << "Load called with non-int dest %" << load.result_type << std::endl;
    std::terminate();
  }

  SpirvValue& source = get_value(kernel, load.pointer);
  auto& source_type = kernel->program->program.types[source.type_id];

  // only do unsigned int loads
  if (is<TypePointer>(source_type)) {
    auto& ptr_ty = std::get<TypePointer>(source_type);
    // this will explode if the type in not an int
    auto& int_desc = std::get<TypeInt>(types[ptr_ty.type]);
    uint64_t result = 0;
    if (int_desc.signedness) {
      std::cerr << "Load called with signed int ptr %" << source.type_id << std::endl;
      std::terminate();
    }
    else {
      if (int_desc.width == 8) {
        auto ptr = reinterpret_cast<uint8_t*>(source.direct);
        result = *ptr;
      }
      else if (int_desc.width == 32) {
        auto ptr = reinterpret_cast<uint32_t*>(source.direct);
        result = *ptr;
      }
      else if (int_desc.width == 64) {
        auto ptr = reinterpret_cast<uint64_t*>(source.direct);
        result = *ptr;
      }
      else {
        std::cerr << "Load called with size other than 8, 32, 64: " << int_desc.width << std::endl;
        std::terminate();
      }

      set_value(kernel, load.result_type, load.result_id, result, {});
      std::cerr << "Processed load from %" << load.pointer << " with result " << result << " in %" << load.result_id << std::endl;
    }
  }
  else {
    std::cerr << "Load called with non-ptr source: " << source.type_id << std::endl;
    std::terminate();
  }

  pc++;
}

void run(InBoundsPtrAccessChain& ibpac, _pi_kernel* kernel, size_t& pc) {
  auto& types = kernel->program->program.types;
  auto& dest_type = types[ibpac.result_type];
  
  // only do base+element for now
  SpirvValue& base = get_value(kernel, ibpac.base);
  SpirvValue& element = get_value(kernel, ibpac.element);
  auto& base_ptr_type = std::get<TypePointer>(types[base.type_id]);
  auto& base_int_desc = std::get<TypeInt>(types[base_ptr_type.type]);
  auto& element_type = std::get<TypeInt>(types[element.type_id]);

  uint64_t result_ptr = base.direct;
  uint64_t element_num = element.direct;

  result_ptr += element_num * (base_int_desc.width/8);
  set_value(kernel, ibpac.result_type, ibpac.result_id, result_ptr, {});

  std::cerr << "Processed ibpac with base %" << ibpac.base << " element %" << ibpac.element << " with val " << element_num << std::endl;
  pc++;
}

void run(Branch& br, _pi_kernel* kernel, size_t& pc) {
  SpirvId dest_label = br.target;
  pc = kernel->kernel.function.labels[dest_label];
  std::cerr << "Processed branch to %" << dest_label << " with addr " << pc << std::endl;
}

void run(Phi& phi, _pi_kernel* kernel, size_t& pc) {
  std::cerr << "Number of blocks: " << phi.blocks.size() << std::endl;
  std::cerr << "Past block: %" << kernel->past_block << " Current block: %" << kernel->current_block << std::endl;
  for (const auto& block : phi.blocks) {
    auto& variable = block.first;
    auto& parent = block.second;
    std::cerr << "Parent: %" << parent << std::endl;
    if (kernel->past_block == parent) {
      auto& value = get_value(kernel, variable);
      set_value(kernel, phi.result_type, phi.result_id, value.direct, value.variable);
      pc++;
      return;
    }
  }
  // if execution gets here, no blocks matched, which is impossible
  std::cerr << "Phi didn't match any parent blocks\n";
  std::terminate();
}

void run(ULessThan& uless, _pi_kernel* kernel, size_t& pc) {
  // we only handle TypeInt inputs
  auto& op1 = get_value(kernel, uless.op1);
  auto& op2 = get_value(kernel, uless.op2);

  auto& types = kernel->program->program.types;
  auto& op1_int_desc = std::get<TypeInt>(types[op1.type_id]);
  auto& op2_int_desc = std::get<TypeInt>(types[op2.type_id]);

  if (op1_int_desc.width == op2_int_desc.width) {
    uint64_t result = op1.direct < op2.direct;
    set_value(kernel, uless.result_type, uless.result_id, result, {});
    std::cerr << "ULessThan %" << uless.op1 << " < %" << uless.op2 << " = " << result << std::endl;
    pc++;
  }
  else {
    std::cerr << "ULessThan called with mismatched ints" << op1_int_desc.width << " " << op2_int_desc.width << std::endl;
    std::terminate();
  }
}

void run(BranchConditional& bc, _pi_kernel* kernel, size_t& pc) {
  auto& condition = get_value(kernel, bc.condition);
  std::cerr << "Condition: " << condition.direct << std::endl;

  if (condition.direct) {
    pc = kernel->kernel.function.labels[bc.true_label];
    std::cerr << "Conditional branch true to %" << bc.true_label << std::endl;
  }
  else {
    pc = kernel->kernel.function.labels[bc.false_label];
    std::cerr << "Conditional branch false to %" << bc.false_label << std::endl;
  }
}

void run(UConvert& uconv, _pi_kernel* kernel, size_t& pc) {
  auto& op = get_value(kernel, uconv.operand);
  auto& types = kernel->program->program.types;
  auto& dest_int_desc = std::get<TypeInt>(types[uconv.result_type]);
  uint64_t result = op.direct;

  if (dest_int_desc.width == 8) {
    result &= 0xFF;
  }
  else if (dest_int_desc.width == 32) {
    result &= 0xFFFFFFFF;
  }

  set_value(kernel, uconv.result_type, uconv.result_id, result, {});
  std::cerr << "UConvert-ing %" << uconv.operand << " to " << dest_int_desc.width << "-bit width" << std::endl;
  pc++;
}

void run(Store& store, _pi_kernel* kernel, size_t& pc) {
  auto& types = kernel->program->program.types;
  auto& ptr = get_value(kernel, store.pointer);
  auto& ptr_ty = std::get<TypePointer>(types[ptr.type_id]);
  auto& int_desc = std::get<TypeInt>(types[ptr_ty.type]);
  auto& object = get_value(kernel, store.object);
  uint64_t ptr_val = ptr.direct;

  if (int_desc.width == 8) {
    auto ptr = reinterpret_cast<uint8_t*>(ptr_val);
    *ptr = object.direct;
  }
  else if (int_desc.width == 32) {
    auto ptr = reinterpret_cast<uint32_t*>(ptr_val);
    *ptr = object.direct;
  }
  else if (int_desc.width == 64) {
    auto ptr = reinterpret_cast<uint64_t*>(ptr_val);
    *ptr = object.direct;
  }
  else {
    std::cerr << "Unimplemented store width: " << int_desc.width << std::endl;
    std::terminate();
  }

  std::cerr << "Stored " << object.direct << " into %" << store.pointer << std::endl;
  pc++;
}

void run(IAdd& iadd, _pi_kernel* kernel, size_t& pc) {
  auto& op1 = get_value(kernel, iadd.op1);
  auto& op2 = get_value(kernel, iadd.op2);

  // we don't handle vector types yet
  auto& types = kernel->program->program.types;
  auto& op1_int_desc = std::get<TypeInt>(types[op1.type_id]);
  auto& op2_int_desc = std::get<TypeInt>(types[op2.type_id]);

  // overflow schmoverflow
  uint64_t result = op1.direct + op2.direct;
  set_value(kernel, iadd.result_type, iadd.result_id, result, {});
  std::cerr << "IAdd %" << iadd.op1 << " + %" << iadd.op2 << " = " << result << std::endl;
  pc++;
}

void run(Return& ret, _pi_kernel* kernel, size_t& pc) {
  std::cerr << "[I] Return\n";
  pc++;
}

void run(FunctionEnd& fend, _pi_kernel* kernel, size_t& pc) {
  std::cerr << "[I] FunctionEnd\n";
  pc++;
}

void allocate_params(_pi_kernel* kernel) {
  for (int i = 0; i < kernel->kernel.function.params.size(); i++) {
    auto& param = kernel->kernel.function.params[i];
    uint64_t mem_ptr = 0;
    if (param.mem_buffer_id != -1) {
      mem_ptr = reinterpret_cast<uint64_t>(kernel->program->context->memory_area[param.mem_buffer_id].data());
    }
    else {
      kernel->layout.resize(32, 0);
      mem_ptr = reinterpret_cast<uint64_t>(kernel->layout.data());
    }
    set_value(kernel, param.result_type, param.result_id, mem_ptr, {});
  }
}

void load_constants(_pi_kernel* kernel) {
  for (const auto& constant : kernel->program->program.constants) {
    const auto& c = constant.second;
    set_value(kernel, c.type, constant.first, c.value, {});
  }
}

void run_on_spire(_pi_kernel* kernel) {
  // interpreter
  auto& program = *(kernel->program);
  auto& context = *(program.context);
  auto& code = kernel->kernel.function.code;
  context.allocate_memories();
  allocate_params(kernel);
  load_constants(kernel);
  kernel->past_block = 0;
  kernel->current_block = 0;

  size_t program_counter = 0;
  while(program_counter < code.size()) {
    auto& inst = code[program_counter];
    std::visit([&](auto&& inst) { 
      std::cerr << "\nPC: " << program_counter << "\n";
      run(inst, kernel, program_counter); 
    }, inst);
  }
}

#undef is

#endif // PI_SCYTHE_HPP
