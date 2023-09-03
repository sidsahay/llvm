// spire (SPIRv Executor)
// dynamic tiled fpga device interpreter

#pragma once

#include <iostream>
#include <cassert>
#include <map>
#include <variant>

// for SPIR-V parser
#include "spirv-tools/libspirv.hpp"
#include "spirv/unified1/spirv.hpp"

// for demangler
#include <cxxabi.h>

namespace spire {

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
        impl::TypeBool
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
        BranchConditional,
        UConvert,
        Store,
        IAdd,
        Return,
        FunctionEnd
    >;
};

using SpirvType = impl::Type;
using SpirvCode = impl::Code;

struct SpirvConstant {
    SpirvId type;
    uint32_t value;
    bool is_spec;

    SpirvConstant() : type(0), value(0), is_spec(false) {}
    SpirvConstant(SpirvId t, uint32_t v, bool is_spec) : type(t), value(v), is_spec(is_spec) {}
};

struct SpirvVariable {
    SpirvId type;
    SpirvStorageClass storage_class;

    SpirvVariable() : type(0), storage_class(0) {}
    SpirvVariable(SpirvId t, SpirvStorageClass sc) : type(t), storage_class(sc) {}

    std::ostream& operator<<(std::ostream& out) {
        out << "SpirvVariable(" << type << ", " << storage_class << ")";
        return out;
    }
};

struct SpirvFunctionParameter {
    SpirvId result_type;
    SpirvId result_id;

    SpirvFunctionParameter() : result_type(0), result_id(0) {}
    SpirvFunctionParameter(SpirvId ty, SpirvId id) : result_type(ty), result_id(id) {}

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

                case spv::OpVariable: {
                    SpirvId result_type, result_id;
                    SpirvStorageClass storage_class;
                    result_type = inst.words[1];
                    result_id = inst.words[2];
                    storage_class = inst.words[3];
                    if (inst.num_words > 4) {
                        std::cerr << "OpVariable with initializer not implemented!\n";
                        std::terminate();
                    }
                    variables[result_id] = SpirvVariable(result_type, storage_class);
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

                    if (kernel_it != kernels.end()) {
                        auto& kernel = kernel_it->second;
                        kernel.function.result_type = result_type;
                        kernel.function.result_id = result_id;
                        kernel.function.function_type = function_type;
                        current_fn = result_id;
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
                            int offset = 3 + 2*num_blocks;
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
                        op1 = inst.words[4];
                        auto& fn = kernels[current_fn].function;
                        fn.code.push_back(impl::ULessThan(result_type, result_id, op1, op2));
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
                        op1 = inst.words[4];
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

                default: {
                    if (entrypoints_done == entrypoints_started) {
                        std::cerr << "Default skipping " << spvOpcodeString(opcode) << std::endl;
                    }
                    else {
                        std::cerr << "Unimplemented opcode: " << spvOpcodeString(opcode) << std::endl;
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

struct MemBuffer {

};


};
