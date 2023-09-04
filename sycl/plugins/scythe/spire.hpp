// spire (SPIRv Executor)
// dynamic tiled fpga device interpreter

#pragma once

#include <iostream>
#include <cassert>
#include <map>
#include <variant>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>

// for SPIR-V parser
#include "spirv-tools/libspirv.hpp"
#include "spirv/unified1/spirv.hpp"

// for demangler
#include <cxxabi.h>

namespace spire {

static size_t mem_buffer_count = 0;

std::string get_last_string(spv_parsed_instruction_t inst) {
    assert(static_cast<spv::Op>(inst.opcode) == spv::Op::OpEntryPoint
        || static_cast<spv::Op>(inst.opcode) == spv::Op::OpName);

    const auto& name_operand = inst.operands[inst.num_operands-1];
    const auto name_start = inst.words + name_operand.offset;
    return {reinterpret_cast<const char*>(name_start)};
}

std::string demangle_kernel_name(std::string kernel_name) {
    int status;
    auto demangled = abi::__cxa_demangle(kernel_name.c_str(), NULL, NULL, &status);
    auto name_str = std::string(demangled);
    free(demangled); // cxa_demangle() mallocs this, so we need to free

    // the real name is after the "const::" in the demangled output
    return name_str.substr(name_str.find("const::") + 7);
}

struct Context {

};

using SpirvId = uint32_t;
using SpirvStorageClass = uint32_t;


namespace impl {
    struct TypeInt {
        size_t width;
        bool signedness;

        TypeInt() : width(0), signedness(false) {}
        TypeInt(size_t w, bool s) : width(w), signedness(s) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypeInt(" << width << ", " << signedness << ")";
            return out;
        }
    };

    struct TypeVector {
        SpirvId type;
        uint32_t count;

        TypeVector() : type(0), count(0) {}
        TypeVector(SpirvId t, uint32_t c) : type(t), count(c) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypeVector(" << type << ", " << count << ")";
            return out;
        }
    };

    struct TypeArray {
        SpirvId type;
        uint32_t length;

        TypeArray() : type(0), length(0) {}
        TypeArray(SpirvId t, uint32_t l) : type(t), length(l) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypeArray(" << type << ", " << length << ")";
            return out;
        }
    };

    // enum struct SpirvStorageClass {
    //     UniformConstant = 0,
    //     Input = 1,
    //     Uniform = 2,
    //     Output = 3,
    //     Workgroup = 4,
    //     CrossWorkgroup = 5,
    //     Private = 6,
    //     Function = 7,
    //     Generic = 8,
    //     PushConstant = 9,
    //     AtomicCounter = 10,
    //     Image = 11,
    //     StorageBuffer = 12,
    //     PhysicalStorageBuffer = 5349,
    //     CodeSectionINTEL = 5605,
    //     DeviceOnlyINTEL = 5936,
    //     HostOnlyINTEL = 5937
    // };

    struct TypePointer {
        SpirvStorageClass storage_class;
        SpirvId type;

        TypePointer() : storage_class(0), type(0) {}
        TypePointer(SpirvStorageClass sc, SpirvId ty) : storage_class(sc), type(ty) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypePointer(" << storage_class << ", " << type << ")";
            return out;
        }
    };

    struct TypeVoid {
        std::ostream& operator<<(std::ostream& out) {
            out << "TypeVoid()";
            return out;
        }
    };

    struct TypeBool {
        std::ostream& operator<<(std::ostream& out) {
            out << "TypeBool()";
            return out;
        }
    };

    struct TypePipe {
        uint32_t access;

        TypePipe(uint32_t a) : access(a) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypePipe()";
            return out;
        }
    };

    struct TypeStruct {
        std::vector<SpirvId> member_types;

        TypeStruct() {}
        TypeStruct(std::vector<SpirvId> mts) : member_types(mts) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypeStruct(";
            for (auto mt : member_types) {
                out << mt << ", ";
            }
            out << ")";
            return out;
        }
    };

    struct TypeFunction {
        SpirvId return_type;
        std::vector<SpirvId> parameter_types;

        TypeFunction() : return_type(0) {}
        TypeFunction(SpirvId ret, std::vector<SpirvId> pts) : return_type(ret), parameter_types(pts) {}

        std::ostream& operator<<(std::ostream& out) {
            out << "TypeFunction(" << return_type << ", ";
            for (auto pt : parameter_types) {
                out << pt << ", ";
            }
            out << ")";
            return out;
        }
    };


    using Type = std::variant<
        impl::TypeInt,
        impl::TypeVector,
        impl::TypePointer,
        impl::TypeVoid,
        impl::TypeArray,
        impl::TypeStruct,
        impl::TypeFunction,
        impl::TypeBool,
        impl::TypePipe
    >;

    struct Label {
        SpirvId result_id;
        Label() : result_id(0) {}
        Label(SpirvId r) : result_id(r) {}
    };

    struct Branch {
        SpirvId target;
        Branch(SpirvId t) : target(t) {}
    };

    struct FunctionCall {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId function;
        std::vector<SpirvId> args;

        FunctionCall(SpirvId rt, SpirvId ri, SpirvId fn, std::vector<SpirvId>& args)
         : result_type(rt), result_id(ri), function(fn), args(args) {}
    };

    struct Bitcast {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId operand;

        Bitcast(SpirvId rt, SpirvId ri, SpirvId o)
         : result_type(rt), result_id(ri), operand(o) {}
    };

    struct Load {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId pointer;
        std::vector<SpirvId> args;

        Load(SpirvId rt, SpirvId ri, SpirvId p, std::vector<SpirvId>& args)
         : result_type(rt), result_id(ri), pointer(p), args(args) {}
    };

    struct InBoundsPtrAccessChain {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId base;
        SpirvId element;
        std::vector<SpirvId> indices;

        InBoundsPtrAccessChain(SpirvId rt, SpirvId ri, SpirvId b, SpirvId e, std::vector<SpirvId>& in)
         : result_type(rt), result_id(ri), base(b), element(e), indices(in) {}
    };

    struct Phi {
        SpirvId result_type;
        SpirvId result_id;
        std::vector<std::pair<SpirvId, SpirvId>> blocks;

        Phi(SpirvId rt, SpirvId ri, std::vector<std::pair<SpirvId, SpirvId>>& b)
         : result_type(rt), result_id(ri), blocks(b) {}
    };

    struct ULessThan {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId op1;
        SpirvId op2;

        ULessThan(SpirvId rt, SpirvId ri, SpirvId o1, SpirvId o2)
         : result_type(rt), result_id(ri), op1(o1), op2(o2) {}
    };

    struct SLessThan {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId op1;
        SpirvId op2;

        SLessThan(SpirvId rt, SpirvId ri, SpirvId o1, SpirvId o2)
         : result_type(rt), result_id(ri), op1(o1), op2(o2) {}
    };

    struct BranchConditional {
        SpirvId condition;
        SpirvId true_label;
        SpirvId false_label;

        BranchConditional(SpirvId c, SpirvId t, SpirvId f)
         : condition(c), true_label(t), false_label(f) {}
    };

    struct UConvert {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId operand;

        UConvert(SpirvId rt, SpirvId ri, SpirvId o)
         : result_type(rt), result_id(ri), operand(o) {}
    };

    struct Store {
        SpirvId pointer;
        SpirvId object;
        std::vector<SpirvId> args;

        Store(SpirvId p, SpirvId o, std::vector<SpirvId>& args)
         : pointer(p), object(o), args(args) {}
    };

    struct IAdd {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId op1;
        SpirvId op2;

        IAdd(SpirvId rt, SpirvId ri, SpirvId o1, SpirvId o2)
         : result_type(rt), result_id(ri), op1(o1), op2(o2) {}
    };

    struct PtrCastToGeneric {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId pointer;

        PtrCastToGeneric(SpirvId rt, SpirvId ri, SpirvId p)
         : result_type(rt), result_id(ri), pointer(p) {}
    };

    struct CreatePipeFromPipeStorage {
        SpirvId result_type;
        SpirvId result_id;
        SpirvId storage;

        CreatePipeFromPipeStorage(SpirvId rt, SpirvId ri, SpirvId s)
         : result_type(rt), result_id(ri), storage(s) {}
    };

    struct Variable {
        SpirvId type;
        SpirvId result_id;

        Variable(SpirvId type, SpirvId result_id) : type(type), result_id(result_id) {}
    };

    struct LifetimeStart {
        SpirvId pointer;
        uint32_t size;

        LifetimeStart(SpirvId ptr, uint32_t size) : pointer(ptr), size(size) {}
    };

    struct LifetimeStop {
        SpirvId pointer;
        uint32_t size;

        LifetimeStop(SpirvId ptr, uint32_t size) : pointer(ptr), size(size) {}
    };

    struct WritePipeBlockingINTEL {
        SpirvId pipe;
        SpirvId pointer;
        SpirvId packet_size;
        SpirvId packet_align;

        WritePipeBlockingINTEL(SpirvId pi, SpirvId po, SpirvId ps, SpirvId pa) 
         : pipe(pi), pointer(po), packet_size(ps), packet_align(pa) {}
    };

    struct ReadPipeBlockingINTEL {
        SpirvId pipe;
        SpirvId pointer;
        SpirvId packet_size;
        SpirvId packet_align;

        ReadPipeBlockingINTEL(SpirvId pi, SpirvId po, SpirvId ps, SpirvId pa) 
         : pipe(pi), pointer(po), packet_size(ps), packet_align(pa) {}
    };

    struct Return {};
    struct FunctionEnd {};

    using Code = std::variant<
        Label,
        FunctionCall,
        Bitcast,
        Load,
        InBoundsPtrAccessChain,
        Branch,
        Phi,
        ULessThan,
        SLessThan,
        BranchConditional,
        UConvert,
        Store,
        IAdd,
        Return,
        FunctionEnd,
        PtrCastToGeneric,
        Variable,
        LifetimeStart,
        LifetimeStop,
        CreatePipeFromPipeStorage,
        WritePipeBlockingINTEL,
        ReadPipeBlockingINTEL
    >;
};

using SpirvType = impl::Type;
using SpirvCode = impl::Code;

struct SpirvConstant {
    SpirvId type;
    uint32_t value;
    bool is_spec;
    std::vector<uint32_t> variable_value;

    SpirvConstant() : type(0), value(0), is_spec(false) {}
    SpirvConstant(SpirvId t, uint32_t v, bool is_spec) : type(t), value(v), is_spec(is_spec) {}
};

struct SpirvVariable {
    SpirvId type;
    SpirvId initializer;
    bool has_initializer;
    SpirvStorageClass storage_class;

    SpirvVariable() : type(0), storage_class(0), has_initializer(false) {}
    SpirvVariable(SpirvId t, SpirvStorageClass sc) : type(t), storage_class(sc), has_initializer(false) {}
    SpirvVariable(SpirvId t, SpirvStorageClass sc, SpirvId i) : type(t), storage_class(sc), initializer(i), has_initializer(true) {}

    std::ostream& operator<<(std::ostream& out) {
        out << "SpirvVariable(" << type << ", " << storage_class << ")";
        return out;
    }
};

// -1 id is invalid
struct MemBuffer {
    int id;
    size_t size;
};

struct SpirvFunctionParameter {
    SpirvId result_type;
    SpirvId result_id;
    int mem_buffer_id;

    SpirvFunctionParameter() : result_type(0), result_id(0), mem_buffer_id(-1) {}
    SpirvFunctionParameter(SpirvId ty, SpirvId id) : result_type(ty), result_id(id), mem_buffer_id(-1) {}

    std::ostream& operator<<(std::ostream& out) {
        out << "SpirvFunctionParameter(" << result_type << ", " << result_id << ")";
        return out;
    }
};

struct SpirvFunction {
    SpirvId result_type;
    SpirvId result_id;
    // ignore Function Control
    SpirvId function_type;

    // function params
    std::vector<SpirvFunctionParameter> params;

    // code
    std::vector<SpirvCode> code;
    std::map<SpirvId, size_t> labels;

    SpirvFunction() : result_type(0), result_id(0), function_type(0) {}
    SpirvFunction(SpirvId rt, SpirvId ri, SpirvId ft) : result_type(rt), result_id(ri), function_type(ft) {}

    std::ostream& operator<<(std::ostream& out) {
        out << "SpirvFunction(" << result_type << ", " << result_id << ", " << function_type << ")";
        return out;
    }
};


struct Program;

struct SpirvValue {
  SpirvId type_id;
  SpirvId id;
  uint64_t direct;
  std::vector<uint32_t> variable;
};

struct Kernel {
    std::string name;
    SpirvId entry_point_id;
    SpirvFunction function;
    Program* program;
    
    Kernel() {}
    Kernel(Program* p) : program(p) {}
};

struct Program {
    std::vector<uint32_t> spirv_words;
    std::map<SpirvId, Kernel> kernels;
    std::map<SpirvId, std::string> names;
    std::map<SpirvId, SpirvType> types;
    std::map<SpirvId, SpirvConstant> constants;
    std::map<SpirvId, SpirvVariable> variables;

    Program(const void* bytes, size_t length) {
        auto spirv = reinterpret_cast<const uint32_t*>(bytes);
        auto num_words = length/sizeof(uint32_t);
        for (size_t i = 0; i < num_words; i++) {
            spirv_words.push_back(spirv[i]);
        }
    }

    Kernel& find_kernel(std::string name) {
        for (auto& k : kernels) {
            auto& kernel = k.second;
            if (kernel.name == name) {
                return kernel;
            }
        }
        // should never reach here!
        std::cerr << "Could not find kernel name " << name << std::endl;
        std::terminate();
    }

    void parse_and_build() {
        spvtools::SpirvTools core(SPV_ENV_UNIVERSAL_1_6);

        auto header_callback = [](spv_endianness_t e, spv_parsed_header_t header) {
            return SPV_SUCCESS;
        };

        SpirvId current_fn = 0;
        bool skip_current_code = false;
        int entrypoints_started = 0;
        int entrypoints_done = 0;

        auto instruction_callback = [&](spv_parsed_instruction_t inst) {
            const spv::Op opcode = static_cast<spv::Op>(inst.opcode);

            switch(opcode) {
                case spv::Op::OpCapability:
                case spv::Op::OpExtInstImport:
                case spv::Op::OpMemoryModel:
                case spv::Op::OpExecutionMode:
                case spv::Op::OpSource:
                case spv::Op::OpDecorate:
                    break;

                case spv::Op::OpEntryPoint: {
                    Kernel kernel(this);
                    kernel.entry_point_id = inst.words[2];
                    kernel.name = get_last_string(inst);
                    kernels[kernel.entry_point_id] = kernel;
                    entrypoints_started++;
                    break;
                }

                case spv::Op::OpName: {
                    names[inst.words[1]] = get_last_string(inst);
                    break;
                }

                case spv::OpTypeInt: {
                    SpirvId result_id = inst.words[1];
                    types[result_id] = impl::TypeInt(inst.words[2], inst.words[3]);
                    break;
                }

                case spv::OpConstant: {
                    SpirvId result_type, result_id;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    // TODO: OpConstant is a variable length instruction
                    // make this variable length too
                    // TODO: check endianness
                    constants[result_id] = SpirvConstant(result_type, inst.words[3], false);
                    break;
                }

                case spv::OpConstantComposite: {
                    SpirvId result_type, result_id;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    auto num_items = inst.num_words - 3;
                    std::vector<uint32_t> items;
                    for (int i = 0; i < num_items; i++) {
                        items.push_back(inst.words[3+i]);
                    }
                    constants[result_id] = SpirvConstant(result_type, 0, false);
                    constants[result_id].variable_value = items;
                    break;
                }

                // TODO: remove duplication
                case spv::OpSpecConstant: {
                    SpirvId result_type, result_id;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    // TODO: OpConstant is a variable length instruction
                    // make this variable length too
                    // TODO: check endianness
                    constants[result_id] = SpirvConstant(result_type, inst.words[3], true);
                    break;
                }

                case spv::OpTypeVector: {
                    SpirvId result_id, component_type;
                    uint32_t component_count;
                    result_id = inst.words[1];
                    component_type = inst.words[2];
                    component_count = inst.words[3];
                    types[result_id] = impl::TypeVector(component_type, component_count);
                    break;
                }

                case spv::OpTypePointer: {
                    SpirvId result_id, type;
                    SpirvStorageClass storage_class;
                    result_id = inst.words[1];
                    storage_class = inst.words[2];
                    type = inst.words[3];
                    types[result_id] = impl::TypePointer(storage_class, type);
                    break;
                }

                case spv::OpTypeVoid: {
                    SpirvId result_id = inst.words[1];
                    types[result_id] = impl::TypeVoid();
                    break;
                }

                case spv::OpTypeArray: {
                    SpirvId result_id, type;
                    uint32_t length;
                    result_id = inst.words[1];
                    type = inst.words[2];
                    length = inst.words[3];
                    types[result_id] = impl::TypeArray(type, length);
                    break;
                }

                case spv::OpTypeStruct: {
                    SpirvId result_id = inst.words[1];
                    auto num_members = inst.num_words - 2;
                    std::vector<SpirvId> members;
                    for (int i = 0; i < num_members; i++) {
                        members.push_back(inst.words[2+i]);
                    }
                    types[result_id] = impl::TypeStruct(members);
                    break;
                }

                case spv::OpTypeFunction: {
                    SpirvId result_id = inst.words[1];
                    SpirvId return_type = inst.words[2];
                    auto num_params = inst.num_words - 3;
                    std::vector<SpirvId> params;
                    for (int i = 0; i < num_params; i++) {
                        params.push_back(inst.words[3+i]);
                    }
                    types[result_id] = impl::TypeFunction(return_type, params);
                    break;
                }

                case spv::OpTypeBool: {
                    SpirvId result_id = inst.words[1];
                    types[result_id] = impl::TypeBool();
                    break;
                }

                // ** Types for Pipes **
                case spv::OpTypePipe: {
                    SpirvId result_id = inst.words[1];
                    uint32_t access = inst.words[2];
                    types[result_id] = impl::TypePipe(access);
                    break;
                }

                case spv::OpVariable: {
                    SpirvId result_type, result_id;
                    SpirvStorageClass storage_class;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    storage_class = inst.words[3];
                    if (current_fn == 0) {
                        if (inst.num_words > 4) {
                            SpirvId init = inst.words[4];
                            variables[result_id] = SpirvVariable(result_type, storage_class, init);
                        }
                        else {
                            variables[result_id] = SpirvVariable(result_type, storage_class);
                        }
                    }
                    else {
                        if (!skip_current_code) {
                            auto& fn = kernels[current_fn].function;
                            fn.code.push_back(impl::Variable(result_type, result_id));
                        }
                    }
                    
                    break;
                }

                // ***Function body instructions***

                case spv::OpFunction: {
                    // if the function is not an entrypoint, ignore it
                    SpirvId result_type, result_id, function_type;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    // ignore Function Control
                    function_type = inst.words[4];
                    auto kernel_it = kernels.find(result_id);
                    current_fn = result_id;

                    if (kernel_it != kernels.end()) {
                        auto& kernel = kernel_it->second;
                        kernel.function.result_type = result_type;
                        kernel.function.result_id = result_id;
                        kernel.function.function_type = function_type;
                        skip_current_code = false;
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                        skip_current_code = true;
                    }
                    break;
                }

                case spv::OpFunctionParameter: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        kernels[current_fn].function.params.emplace_back(result_type, result_id);
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpLabel: {
                    if (!skip_current_code) {
                        SpirvId result_id;
                        result_id = inst.words[1];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Label(result_id));
                        // store the idx of the label so that it can be jumped to
                        auto label_idx = fn.code.size() - 1;
                        fn.labels[result_id] = label_idx;
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpFunctionCall: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, function;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        function = inst.words[3];
                        auto num_args = inst.num_words - 4;
                        std::vector<SpirvId> args;
                        for (int i = 0; i < num_args; i++) {
                            args.push_back(inst.words[4+i]);
                        }
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::FunctionCall(result_type, result_id, function, args));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpBitcast: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, operand;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        operand = inst.words[3];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Bitcast(result_type, result_id, operand));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpLoad: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, pointer;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        pointer = inst.words[3];
                        auto num_args = inst.num_words - 4;
                        std::vector<SpirvId> args;
                        for (int i = 0; i < num_args; i++) {
                            args.push_back(inst.words[4+i]);
                        }
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Load(result_type, result_id, pointer, args));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpInBoundsPtrAccessChain: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, base, element;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        base = inst.words[3];
                        element = inst.words[4];
                        auto num_indices = inst.num_words - 5;
                        std::vector<SpirvId> indices;
                        for (int i = 0; i < num_indices; i++) {
                            indices.push_back(inst.words[5+i]);
                        }
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::InBoundsPtrAccessChain(result_type, result_id, base, element, indices));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpBranch: {
                    if (!skip_current_code) {
                        SpirvId result_id = inst.words[1];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Branch(result_id));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpPhi: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        auto num_blocks = (inst.num_words - 3)/2;
                        std::vector<std::pair<SpirvId, SpirvId>> blocks;
                        for (int i = 0; i < num_blocks; i++) {
                            int offset = 3 + 2*i;
                            blocks.push_back({inst.words[offset], inst.words[offset+1]});
                        }
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Phi(result_type, result_id, blocks));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpULessThan: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, op1, op2;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        op1 = inst.words[3];
                        op2 = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::ULessThan(result_type, result_id, op1, op2));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpSLessThan: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, op1, op2;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        op1 = inst.words[3];
                        op2 = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::SLessThan(result_type, result_id, op1, op2));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpBranchConditional: {
                    if (!skip_current_code) {
                        SpirvId condition, t, f;
                        condition = inst.words[1];
                        t = inst.words[2];
                        f = inst.words[3];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::BranchConditional(condition, t, f));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpUConvert: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, operand;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        operand = inst.words[3];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::UConvert(result_type, result_id, operand));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpStore: {
                    if (!skip_current_code) {
                        SpirvId pointer, object;
                        pointer = inst.words[1];
                        object = inst.words[2];
                        auto num_args = inst.num_words - 3;
                        std::vector<SpirvId> args;
                        for (int i = 0; i < num_args; i++) {
                            args.push_back(inst.words[3+i]);
                        }
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Store(pointer, object, args));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpIAdd: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, op1, op2;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        op1 = inst.words[3];
                        op2 = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::IAdd(result_type, result_id, op1, op2));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpReturn: {
                    if (!skip_current_code) {
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::Return());
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpFunctionEnd: {
                    if (!skip_current_code) {
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::FunctionEnd());
                        skip_current_code = false;
                        current_fn = 0;
                        entrypoints_done++;
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                // ** Insts for Pipes **
                case spv::OpPtrCastToGeneric: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, pointer;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        pointer = inst.words[3];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::PtrCastToGeneric(result_type, result_id, pointer));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpLifetimeStart: {
                    if (!skip_current_code) {
                        SpirvId ptr = inst.words[1];
                        uint32_t size = inst.words[2];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::LifetimeStart(ptr, size));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpLifetimeStop: {
                    if (!skip_current_code) {
                        SpirvId ptr = inst.words[1];
                        uint32_t size = inst.words[2];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::LifetimeStop(ptr, size));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpCreatePipeFromPipeStorage: {
                    if (!skip_current_code) {
                        SpirvId result_type, result_id, storage;
                        result_type = inst.words[1];
                        result_id = inst.words[2];
                        storage = inst.words[3];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::CreatePipeFromPipeStorage(result_type, result_id, storage));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpWritePipeBlockingINTEL: {
                    if (!skip_current_code) {
                        SpirvId pipe, pointer, size, align;
                        pipe = inst.words[1];
                        pointer = inst.words[2];
                        size = inst.words[3];
                        align = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::WritePipeBlockingINTEL(pipe, pointer, size, align));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                case spv::OpReadPipeBlockingINTEL: {
                    if (!skip_current_code) {
                        SpirvId pipe, pointer, size, align;
                        pipe = inst.words[1];
                        pointer = inst.words[2];
                        size = inst.words[3];
                        align = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::ReadPipeBlockingINTEL(pipe, pointer, size, align));
                    }
                    else {
                        std::cerr << "Skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    break;
                }

                

                default: {
                    auto f = kernels.find(current_fn);
                    if (f == kernels.end()) {
                        #ifdef SPIRE_VERBOSE
                        std::cerr << "Default skipping " << spvOpcodeString(opcode) << std::endl;
                        #endif
                    }
                    else {
                        #ifdef SPIRE_VERBOSE
                        std::cerr << "Unimplemented opcode: " << spvOpcodeString(opcode) << std::endl;
                        #endif
                        std::terminate();
                    }
                }
            }
            return SPV_SUCCESS;
        };

        if(!core.Parse(spirv_words, header_callback, instruction_callback)) {
            std::cerr << "[spv] parsing error\n";
        }
    }
};

struct Queue {

};

#define is std::holds_alternative
using namespace impl;

// TODO: refactor to be more C++-y
struct Interpreter {
    Program* program;
    std::vector<Kernel*> kernels;
    std::vector<size_t> pcs;
    std::vector<size_t> past_blocks;
    std::vector<size_t> current_blocks;
    std::map<SpirvId, SpirvType>* types;

    std::vector<MemBuffer*> memories;
    std::map<size_t, std::vector<uint8_t>> memory_area;
    std::map<SpirvId, SpirvValue> values;

    // dummy for layout object
    std::vector<uint8_t> layout;

    Interpreter() : program(nullptr), types(nullptr) {
        kernel_thread = std::thread([&]() {
            process();
        });
    }

    void load_program(Program* p) {
        program = p;
        types = &(p->types);
        kernels.clear();
    }

    void load_kernel(Kernel* k) {
        kernels.push_back(k);
        pcs.push_back(0);
        past_blocks.push_back(0);
        current_blocks.push_back(0);
        kernel_done.push_back(false);
        allocate_params(k);
    }

    void add_memory(MemBuffer* m) {
        memories.push_back(m);
    }

    SpirvValue& get_value(SpirvId id) {
        if (values.find(id) == values.end()) {
            std::cerr << "Could not find value of id %" << id << std::endl;
            std::terminate();
        }
        return values[id];
    }

    void set_value(SpirvId type_id, SpirvId id, uint64_t direct, std::vector<uint32_t> variable) {
        values[id] = {type_id, id, direct, variable};
    }

    void allocate_memories() {
        for (const auto& mem : memories) {
            memory_area[mem->id].resize(mem->size, 0);
        }
    }

    void allocate_memory(size_t id, size_t size) {
        memory_area[id].resize(size, 0);
    }

    void allocate_params(Kernel* kernel) {
        for (int i = 0; i < kernel->function.params.size(); i++) {
            auto& param = kernel->function.params[i];
            uint64_t mem_ptr = 0;
            if (param.mem_buffer_id != -1) {
               mem_ptr = reinterpret_cast<uint64_t>(memory_area[param.mem_buffer_id].data());
            }
            else {
                layout.resize(32, 0);
                mem_ptr = reinterpret_cast<uint64_t>(layout.data());
            }
            set_value(param.result_type, param.result_id, mem_ptr, {});
        }
    }

    void load_constants() {
        for (const auto& constant : program->constants) {
            const auto& c = constant.second;
            set_value(c.type, constant.first, c.value, c.variable_value);
        }
    }

    void run(Label& label, size_t idx) {
        std::cerr << "Crossed label %" << label.result_id << std::endl;
        past_blocks[idx] = current_blocks[idx];
        current_blocks[idx] = label.result_id;
        pcs[idx]++;
    }

    void run(FunctionCall& fcall, size_t idx) {
        std::cerr << "Ignoring function call %" << fcall.function << std::endl;
        pcs[idx]++;
    }

    void run(Bitcast& bcast, size_t idx) {
        auto& dest_type = types->at(bcast.result_type);

        // bitcast can only handle pointer destinations
        if (!is<impl::TypePointer>(dest_type)) {
            std::cerr << "Bitcast called with non-pointer destination %" << bcast.result_type << std::endl;
            std::terminate();
        }

        SpirvValue& source = get_value(bcast.operand);
        auto& source_type = types->at(source.type_id);
        
        // only handle pointer sources
        if (is<impl::TypePointer>(source_type)) {
            // just change the pointer type and copy over the direct value
            set_value(bcast.result_type, bcast.result_id, source.direct, {});  
        }
        else {
            std::cerr << "Bitcast called with non-pointer source %" << source.type_id << std::endl;
            std::terminate();
        }
        
        std::cerr << "Processed bitcast from %" << source.type_id << " to %" << bcast.result_type << std::endl;
        pcs[idx]++;
    }

    void run(Load& load, size_t idx) {
        auto& dest_type = types->at(load.result_type);

        // we only do int loads for now
        if (!is<impl::TypeInt>(dest_type)) {
            std::cerr << "Load called with non-int dest %" << load.result_type << std::endl;
            std::terminate();
        }

        SpirvValue& source = get_value(load.pointer);
        auto& source_type = types->at(source.type_id);

        // only do unsigned int loads
        if (is<impl::TypePointer>(source_type)) {
            auto& ptr_ty = std::get<impl::TypePointer>(source_type);
            // this will explode if the type in not an int
            auto& int_desc = std::get<impl::TypeInt>(types->at(ptr_ty.type));
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

                set_value(load.result_type, load.result_id, result, {});
                std::cerr << "Processed load from %" << load.pointer << " with result " << result << " in %" << load.result_id << std::endl;
            }
        }
        else {
            std::cerr << "Load called with non-ptr source: " << source.type_id << std::endl;
            std::terminate();
        }

        pcs[idx]++;
    }

    void run(InBoundsPtrAccessChain& ibpac, size_t idx) {
        auto& dest_type = types->at(ibpac.result_type);
        
        // only do base+element for now
        SpirvValue& base = get_value(ibpac.base);
        SpirvValue& element = get_value(ibpac.element);
        auto& base_ptr_type = std::get<impl::TypePointer>(types->at(base.type_id));
        auto& base_int_desc = std::get<impl::TypeInt>(types->at(base_ptr_type.type));
        auto& element_type = std::get<impl::TypeInt>(types->at(element.type_id));

        uint64_t result_ptr = base.direct;
        uint64_t element_num = element.direct;

        result_ptr += element_num * (base_int_desc.width/8);
        set_value(ibpac.result_type, ibpac.result_id, result_ptr, {});

        std::cerr << "Processed ibpac with base %" << ibpac.base << " element %" << ibpac.element << " with val " << element_num << std::endl;
        pcs[idx]++;
    }

    void run(Branch& br, size_t idx) {
        SpirvId dest_label = br.target;
        pcs[idx] = kernels[idx]->function.labels[dest_label];
        std::cerr << "Processed branch to %" << dest_label << " with addr " << pcs[idx] << std::endl;
    }

    void run(Phi& phi, size_t idx) {
        std::cerr << "Number of blocks: " << phi.blocks.size() << std::endl;
        std::cerr << "Past block: %" << past_blocks[idx] << " Current block: %" << current_blocks[idx] << std::endl;
        for (const auto& block : phi.blocks) {
            auto& variable = block.first;
            auto& parent = block.second;
            std::cerr << "Parent: %" << parent << std::endl;
            if (past_blocks[idx] == parent) {
                auto& value = get_value(variable);
                set_value(phi.result_type, phi.result_id, value.direct, value.variable);
                pcs[idx]++;
                return;
            }
        }
        // if execution gets here, no blocks matched, which is impossible
        std::cerr << "Phi didn't match any parent blocks\n";
        std::terminate();
    }

    void run(ULessThan& uless, size_t idx) {
        // we only handle TypeInt inputs
        auto& op1 = get_value(uless.op1);
        auto& op2 = get_value(uless.op2);

        auto& op1_int_desc = std::get<impl::TypeInt>(types->at(op1.type_id));
        auto& op2_int_desc = std::get<impl::TypeInt>(types->at(op2.type_id));

        if (op1_int_desc.width == op2_int_desc.width) {
            uint64_t result = op1.direct < op2.direct;
            set_value(uless.result_type, uless.result_id, result, {});
            std::cerr << "ULessThan %" << uless.op1 << " < %" << uless.op2 << " = " << result << std::endl;
            pcs[idx]++;
        }
        else {
            std::cerr << "ULessThan called with mismatched ints" << op1_int_desc.width << " " << op2_int_desc.width << std::endl;
            std::terminate();
        }
    }

    void run(BranchConditional& bc, size_t idx) {
        auto& condition = get_value(bc.condition);
        std::cerr << "Condition: " << condition.direct << std::endl;

        if (condition.direct) {
            pcs[idx] = kernels[idx]->function.labels[bc.true_label];
            std::cerr << "Conditional branch true to %" << bc.true_label << std::endl;
        }
        else {
            pcs[idx] = kernels[idx]->function.labels[bc.false_label];
            std::cerr << "Conditional branch false to %" << bc.false_label << std::endl;
        }
    }

    void run(UConvert& uconv, size_t idx) {
        auto& op = get_value(uconv.operand);
        auto& dest_int_desc = std::get<impl::TypeInt>(types->at(uconv.result_type));
        uint64_t result = op.direct;

        if (dest_int_desc.width == 8) {
            result &= 0xFF;
        }
        else if (dest_int_desc.width == 32) {
            result &= 0xFFFFFFFF;
        }

        set_value(uconv.result_type, uconv.result_id, result, {});
        std::cerr << "UConvert-ing %" << uconv.operand << " to " << dest_int_desc.width << "-bit width" << std::endl;
        pcs[idx]++;
    }

    void run(Store& store, size_t idx) {
        auto& ptr = get_value(store.pointer);
        auto& ptr_ty = std::get<impl::TypePointer>(types->at(ptr.type_id));
        auto& int_desc = std::get<impl::TypeInt>(types->at(ptr_ty.type));
        auto& object = get_value(store.object);
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
        pcs[idx]++;
    }

    void run(IAdd& iadd, size_t idx) {
        auto& op1 = get_value(iadd.op1);
        auto& op2 = get_value(iadd.op2);

        // we don't handle vector types yet
        auto& op1_int_desc = std::get<impl::TypeInt>(types->at(op1.type_id));
        auto& op2_int_desc = std::get<impl::TypeInt>(types->at(op2.type_id));

        // overflow schmoverflow
        uint64_t result = op1.direct + op2.direct;
        set_value(iadd.result_type, iadd.result_id, result, {});
        std::cerr << "IAdd %" << iadd.op1 << " + %" << iadd.op2 << " = " << result << std::endl;
        pcs[idx]++;
    }

    void run(Return& ret, size_t idx) {
        std::cerr << "[I] Return\n";
        kernel_done[idx] = true;
        pcs[idx]++;
    }

    void run(FunctionEnd& fend, size_t idx) {
        std::cerr << "[I] FunctionEnd\n";
        kernel_done[idx] = true;
        pcs[idx]++;
    }

    std::map<SpirvId, SpirvId> ptrstorage_map;
    void run(PtrCastToGeneric& pctg, size_t idx) {
        auto& ptr = get_value(pctg.pointer);
        set_value(pctg.result_type, pctg.result_id, ptr.direct, {});
        ptrstorage_map[pctg.result_id] = pctg.pointer;
        std::cerr << "PtrCastToGeneric on %" << pctg.pointer << std::endl;
        pcs[idx]++;
    }

    // TODO: move
    std::map<SpirvId, std::vector<uint8_t>> variable_storage;

    void run(Variable& var, size_t idx) {
        // need to allocate here because LifetimeStart 
        // stores a uchar*, not the ptr to the actual variable
        // ...why
        auto& ptr_ty = std::get<TypePointer>(types->at(var.type));
        auto& int_desc = std::get<TypeInt>(types->at(ptr_ty.type));

        variable_storage[var.result_id].resize(int_desc.width/8, 0);
        uint64_t ptr_val = reinterpret_cast<uint64_t>(variable_storage[var.result_id].data());
        set_value(var.type, var.result_id, ptr_val, {});
        
        std::cerr << "Saw variable %" << var.result_id << std::endl;
        pcs[idx]++;
    }

    void load_variables() {
        for (const auto& v : program->variables) {
            const auto& result_id = v.first;
            const auto& var = v.second;    
            auto& ptr_ty = std::get<TypePointer>(types->at(var.type));
            auto& pointee_ty = types->at(ptr_ty.type);

            // support int and struct variables
            if (is<TypeInt>(pointee_ty)) {
                auto& int_desc = std::get<TypeInt>(pointee_ty);
                variable_storage[result_id].resize(int_desc.width/8, 0);
                if (var.has_initializer) {
                    std::cerr << "Inits for int variables not supported\n";
                    std::terminate();
                }      
            }
            else if (is<TypeStruct>(pointee_ty)) {
                auto& struct_desc = std::get<TypeStruct>(pointee_ty);
                // only support struct of ints
                size_t total_bytes = 0;
                for (auto& m : struct_desc.member_types) {
                    auto& member_int_desc = std::get<TypeInt>(types->at(m));
                    total_bytes += member_int_desc.width/8;
                }
                variable_storage[result_id].resize(total_bytes, 0);

                std::cerr << "Variable has total len " << total_bytes << "\n";

                if (var.has_initializer) {
                    auto& init_val = get_value(var.initializer);
                    size_t offset = 0;
                    auto base = variable_storage[result_id].data();
                    for (auto v : init_val.variable) {
                        auto& init = get_value(v);
                        uint64_t value = init.direct;
                        std::cout << "V: " << value << std::endl;
                        auto& v_desc = std::get<TypeInt>(types->at(init.type_id));
                        size_t sz = v_desc.width/8;
                        auto offset_ptr = base + offset;
                        if (sz == 1) {
                            *offset_ptr = value;
                        }
                        else if (sz == 4) {
                            auto p = reinterpret_cast<uint32_t*>(offset_ptr);
                            *p = value;
                        }
                        else if (sz == 8) {
                            auto p = reinterpret_cast<uint64_t*>(offset_ptr);
                            *p = value;
                        }
                        else {
                            std::cerr << "Unimplemented struct member size\n";
                            std::terminate();
                        }
                        offset += sz;
                    }
                    // auto dst_ptr = reinterpret_cast<uint8_t*>(variable_storage[result_id].data());
                    // auto src_ptr = reinterpret_cast<uint8_t*>(init_val.variable.data());
                    // for (int i = 0; i < total_bytes; i++) {
                    //     dst_ptr[i] = src_ptr[i];
                    // }
                }
            }
            else {
                std::cerr << "warning: Unimplemented variable type for var %" << result_id << "\n";
            }

            uint64_t ptr_val = reinterpret_cast<uint64_t>(variable_storage[result_id].data());
            set_value(var.type, result_id, ptr_val, {});   
        }
    }

    void run(LifetimeStart& ls, size_t idx) {
        // do nothing rn
        std::cerr << "LifetimeStart\n";
        pcs[idx]++;
    }
    void run(LifetimeStop& ls, size_t idx) {
        // do nothing rn
        std::cerr << "LifetimeStop\n";
        pcs[idx]++;
    }

    void run(SLessThan& sless, size_t idx) {
        // we only handle TypeInt inputs
        auto& op1 = get_value(sless.op1);
        auto& op2 = get_value(sless.op2);

        auto& op1_int_desc = std::get<impl::TypeInt>(types->at(op1.type_id));
        auto& op2_int_desc = std::get<impl::TypeInt>(types->at(op2.type_id));

        if (op1_int_desc.width == op2_int_desc.width) {
            uint64_t result = int64_t(op1.direct) < int64_t(op2.direct);
            set_value(sless.result_type, sless.result_id, result, {});
            std::cerr << "SLessThan %" << sless.op1 << " < %" << sless.op2 << " = " << result << std::endl;
            pcs[idx]++;
        }
        else {
            std::cerr << "SLessThan called with mismatched ints" << op1_int_desc.width << " " << op2_int_desc.width << std::endl;
            std::terminate();
        }
    }
    
    struct Pipe {
        std::deque<uint64_t> storage;
        size_t max_size;

        Pipe() : max_size(16) {}
        Pipe(size_t sz) : max_size(sz) {}
        
        bool read(uint64_t& data) {
            if (storage.empty()) {
                return false;
            }
            else {
                data = storage.front();
                storage.pop_front();
                return true;
            }
        }

        bool write(uint64_t data) {
            if (storage.size() >= max_size) {
                return false;
            }
            else {
                storage.push_back(data);
                return true;
            }
        }
    };

    std::map<SpirvId, Pipe> pipes;

    void run(CreatePipeFromPipeStorage& cpfps, size_t idx) {
        auto& storage = get_value(cpfps.storage);
        
        // pipestorage is 3x 4byte ints
        auto pipe_specs = reinterpret_cast<uint32_t*>(storage.direct);
        uint32_t width = pipe_specs[0];
        uint32_t align = pipe_specs[1];
        uint32_t capacity = pipe_specs[2];
        std::cerr << "Creating pipe of specs " << width << " " << align << " " << capacity << std::endl;

        // this instr is called repeatedly to conceptually make a pipe
        // (why cant it be lifted??)
        // therefore only make pipe if it doesnt exist

        // find the actual storage ID
        auto actual_storage_id = ptrstorage_map[cpfps.storage];

        auto pipe = pipes.find(actual_storage_id);
        if (pipe == pipes.end()) {
            pipes[actual_storage_id] = {capacity};
        }

        set_value(cpfps.result_type, cpfps.result_id, actual_storage_id, {});
        pcs[idx]++;
    }

    void run(WritePipeBlockingINTEL& wpbi, size_t idx) {
        // get the data to write
        // we need to deref pointer
        SpirvValue& source = get_value(wpbi.pointer);
        auto& source_type = types->at(source.type_id);
        auto& ptr_ty = std::get<impl::TypePointer>(source_type);
        // this will explode if the type in not an int
        auto& int_desc = std::get<impl::TypeInt>(types->at(ptr_ty.type));
        
        uint64_t result = 0;

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
            std::cerr << "WritePipeBlockingINTEL called with size other than 8, 32, 64: " << int_desc.width << std::endl;
            std::terminate();
        }

        // do the actual write
        // lookup actual OpVariable storage ID from 
        // ID returned by CreatePipe
        auto& created_pipe = get_value(wpbi.pipe);
        auto& pipe = pipes[created_pipe.direct];
        
        // only incr PC on successful write, so it'll spin on capacity block
        if (pipe.write(result)) {
            pcs[idx]++;
        }
        else {
            std::cerr << "WritePipeBlockingINTEL stalled on pipe %" << created_pipe.direct << std::endl;
        }
    }

    void run(ReadPipeBlockingINTEL& rpbi, size_t idx) {
        // do the actual read
        auto& created_pipe = get_value(rpbi.pipe);
        auto& pipe = pipes[created_pipe.direct];
        uint64_t result = 0;

        // only incr PC on successful read, so it'll spin on empty
        if (pipe.read(result)) {
            auto& ptr = get_value(rpbi.pointer);
            auto& ptr_ty = std::get<impl::TypePointer>(types->at(ptr.type_id));
            auto& int_desc = std::get<impl::TypeInt>(types->at(ptr_ty.type));
            uint64_t ptr_val = ptr.direct;

            if (int_desc.width == 8) {
                auto ptr = reinterpret_cast<uint8_t*>(ptr_val);
                *ptr = result;
            }
            else if (int_desc.width == 32) {
                auto ptr = reinterpret_cast<uint32_t*>(ptr_val);
                *ptr = result;
            }
            else if (int_desc.width == 64) {
                auto ptr = reinterpret_cast<uint64_t*>(ptr_val);
                *ptr = result;
            }
            else {
                std::cerr << "Unimplemented read width: " << int_desc.width << std::endl;
                std::terminate();
            }

            std::cerr << "ReadPipeBlockingINTEL read " << result << " into %" << rpbi.pointer << std::endl;
            pcs[idx]++;
        }
        else {
            std::cerr << "ReadPipeBlockingINTEL stalled on pipe %" << created_pipe.direct << std::endl;
        }
    }

    void execute() {
        // choose kernel 0 for now
        auto& code = kernels[0]->function.code;

        while(pcs[0] < code.size()) {
            auto& inst = code[pcs[0]];
            std::cerr << "\nPC: " << pcs[0] << "\n";
            std::visit([&](auto&& in) {
                run(in, 0);
            }, inst);
        }
    }


    void execute_step(size_t idx) {
        auto& code = kernels[idx]->function.code;
        auto& inst = code[pcs[idx]];
        std::visit([&](auto&& in) {
            run(in, idx);
        }, inst);
    }

    std::mutex m;
    std::thread kernel_thread;
    bool go;
    int chunk;
    std::condition_variable cv;
    std::vector<bool> kernel_done;

    void advance_chunk(int num_insts) {
        chunk = num_insts;
        {
            std::lock_guard<std::mutex> lock(m);
            go = true;
        }
        cv.notify_one();

        {
            std::unique_lock<std::mutex> lock(m);
            cv.wait(lock);
        }
    }

    void process() {
        while(true) {
            std::unique_lock<std::mutex> lock(m);
            cv.wait(lock);
            if (go) {
                for (int j = 0; j < chunk; j++) {
                    for (int i = 0; i < kernels.size(); i++) {
                        if (!kernel_done[i]) {
                            execute_step(i);
                        }
                    }
                }
                go = false;
            }
            lock.unlock();
            cv.notify_one();
        }
    }

    bool is_done(size_t idx) {
        return kernel_done[idx];
    }

    void wait(size_t idx) {
        bool done = is_done(idx);
        while (!done) {
            advance_chunk(5);
            done = is_done(idx);
        }
    }

    ~Interpreter() {

    }

} global_interpreter;

#undef is

};
