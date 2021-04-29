module Hatchery

using PyCall
using Unicorn
using Printf
using Distributed


@info "Loading Hatchery..."

Angr = PyNULL()
Capstone = PyNULL()

function __init__()
    @info "Initializing Python libraries..."
    copy!(Angr, pyimport("angr"))
    copy!(Capstone, pyimport("capstone"))
    #@show Angr
    #@show Capstone
end

MEMORY = nothing

const PAGE_SIZE = 0x1000
const PAGE_BITS = Int(log(2, PAGE_SIZE))

const STACK_SIZE = 0x1000 # TODO: this should be tunable

Base.@kwdef mutable struct Segment
    address::UInt64
    perms::Perm.t
    data::Vector{UInt8}
    label::Union{Nothing, Symbol}
end

function align(n::Integer)::Integer
    (n >> PAGE_BITS) << PAGE_BITS
end

function align!(s::Segment)
    dif = s.address - align(s.address)
    @assert dif >= 0
    if dif > 0
        s.data = vcat(zeros(UInt8, dif), s.data)
        s.address = align(s.address)
    end
    # now make sure the size is aligned
    size = length(s.data)
    dif2 = size - align(size)
    @assert dif2 >= 0
    if dif2 > 0
        comp = PAGE_SIZE - (size % PAGE_SIZE)
        s.data = vcat(s.data, zeros(UInt8, comp))
    end
    @assert length(s.data) % PAGE_SIZE == 0
    return
end

Base.@kwdef struct MemoryImage
    segs::Vector{Segment}
    path::String
    angr_proj::PyObject
    ## TODO: store an initial register state here, too? 
end

function random_address(;mem::MemoryImage=MEMORY, perms=Perm.EXEC, Type=UInt32)
    seg = rand([s for s in mem.segs if s.perms & perms != Perm.NONE])
    return rand(seg.address:(seg.address + length(seg.data))) |> Type
end


function get_stack(mem::MemoryImage)::Union{Nothing, Segment}
    for s in mem.segs
        if s.label == :stack
            return s
        end
    end
    return nothing
end

function load(path)
    global MEMORY

    if typeof(MEMORY) ≡ MemoryImage && MEMORY.path == path
        return MEMORY
    end
    @info "Loading binary from $(path)..."
    proj = Angr.Project(path)
    mem = proj.loader.memory

    function angr_perms(seg)
        perm = Perm.NONE
        seg.is_readable && (perm |= Perm.READ)
        seg.is_writable && (perm |= Perm.WRITE)
        seg.is_executable && (perm |= Perm.EXEC)
        return perm
    end

    segments = [
        Segment(
            address = s.vaddr,
            perms = angr_perms(s),
            data = Vector{UInt8}(mem.load(s.min_addr, s.memsize)),
            label = nothing,
        )
        for
        s in vcat([[s for s in obj.segments] for obj in proj.loader.all_elf_objects]...)
    ]
    align!.(segments)
    stack_addr = maximum(s.address + length(s.data) for s in segments)
    stack = Segment(
        address = stack_addr,
        perms = Perm.READ | Perm.WRITE,
        data = zeros(UInt8, STACK_SIZE),
        label = :stack,
    )
    push!(segments, stack)

    MEMORY = MemoryImage(segs = segments, path = path, angr_proj = proj)

end

function initialize_emulator()::Emulator
    initialize_emulator(MEMORY)
end

function initialize_emulator(memory::MemoryImage)::Emulator
    # TODO: don't hardcode the architecture
    emu = Emulator(Arch.X86, Mode.MODE_32)
    for s in memory.segs
        if s.perms & Perm.WRITE == Perm.NONE
            mem_map_array!(
                emu,
                address = s.address,
                size = length(s.data),
                array = s.data,
                perms = s.perms,
            )
        else
            mem_map!(emu, address = s.address, size = length(s.data), perms = s.perms)
            mem_write!(emu, address = s.address, bytes = s.data)
        end
    end
    emu
end

function load_chain!(emu::Emulator, chain::Vector{N}) where {N <: Integer}
    stack = get_stack(MEMORY)
    if stack == nothing
        @error "No stack found in emulator. Cannot load chain."
    end
    sp = UInt64(stack.address + STACK_SIZE / 2)
    payload = reinterpret(UInt8, chain)
    if length(payload) > STACK_SIZE/2
      payload = payload[1:Int(STACK_SIZE/2)]
    end
    mem_write!(emu, address = sp, bytes = payload)
    reg_write!(emu, register = Unicorn.stack_pointer(emu), value = sp + word_size(emu))
end

Base.@kwdef struct Inst
    address::UInt64
    code::Vector{UInt8}
end

const MAX_STEPS = 0x1000 # TODO put in config

# fields with leading underscores are uncommitted.
# committment takes place at rets, and perhaps other composability points
mutable struct Profiler
    arch::Arch.t
    mode::Mode.t
    _insts::Vector{Inst}
    insts::Vector{Inst}
    regs::Dict{Register, UInt64}
    ret_count::Int

    Profiler(arch::Arch.t, mode::Mode.t) = begin
        arch = arch
        mode = mode
        _insts = []
        sizehint!(_insts, MAX_STEPS)
        insts = []
        sizehint!(insts, MAX_STEPS)
        regs = Dict{Register, UInt64}()
        sizehint!(regs, 32)
        new(arch, mode, _insts, insts, regs, 0)
    end
end

struct Profile
    arch::Arch.t
    mode::Mode.t
    insts::Vector{Inst}
    regs::Dict{Register, UInt64}
    ret_count::Int
    exit_code::Unicorn.UcError.t

    Profile(profiler::Profiler, exit_code::Unicorn.UcError.t) = new(profiler.arch, profiler.mode, profiler.insts, profiler.regs, profiler.ret_count, exit_code)
end

function cs_arch(arch::Arch.t)
    arch == Arch.X86 && return Capstone.CS_ARCH_X86
    arch == Arch.ARM && return Capstone.CS_ARCH_ARM
    arch == Arch.ARM64 && return Capstone.CS_ARCH_ARM64
    arch == Arch.M64K && return Capstone.CS_ARCH_M68K
    arch == Arch.MIPS && return Capstone.CS_ARCH_MIPS
    arch == Arch.SPARC && return Capstone.CS_ARCH_SPARC
    error("should be unreachable")
end

function cs_mode(mode::Mode.t)
    mode == Mode.MODE_64 && return Capstone.CS_MODE_64
    mode == Mode.MODE_32 && return Capstone.CS_MODE_32
    mode == Mode.MODE_16 && return Capstone.CS_MODE_16
    mode == Mode.ARM && return Capstone.CS_MODE_ARM
    mode == Mode.THUMB && return Capstone.CS_MODE_THUMB
    error("mode conversion unimplemented (TODO)")
end

function Base.show(io::IO, profile::Profile)
    w = 70
    println(io, "--- Profile $(repeat("-", w-12))")
    println(io, "Registers:")
    for kv in sort(profile.regs)
        @printf io "\t%s => 0x%x\n" kv.first kv.second
    end
    println(io, "Trace:")
    cs = Capstone.Cs(cs_arch(profile.arch), cs_mode(profile.mode))
    for inst in profile.insts
        for dis in cs.disasm(inst.code, inst.address)
            @printf io "\t0x%x:\t%s\t%s\n" dis.address dis.mnemonic dis.op_str
        end
    end
    println(io, "Return count: $(profile.ret_count)")
    println(io, "Exit code: $(profile.exit_code)")
    println(io, repeat("-", w))
end

#=
x86/x86_64 RETURN INSTRUCTIONS

| Opcode* | Instruction | Op/En | 64-Bit | Compat/Leg | Description                                                      |
|---------+-------------+-------+--------+------------+------------------------------------------------------------------|
| C3      | RET         | ZO    | Valid  | Valid      | Near return to calling procedure.                                |
| CB      | RET         | ZO    | Valid  | Valid      | Far return to calling procedure.                                 |
| C2 iw   | RET imm16   | I     | Valid  | Valid      | Near return to calling procedure and pop imm16 bytes from stack. |
| CA iw   | RET imm16   | I     | Valid  | Valid      | Far return to calling procedure and pop imm16 bytes from stack.  |

=#
function is_ret(inst::Inst, arch::Arch.t, mode::Mode.t)::Bool
    if arch == Arch.X86 
        return ((length(inst.code) == 1 && (inst.code[1] == 0xc3 ||
                                            inst.code[1] == 0xcb))
                || (length(inst.code) == 3 && (inst.code[1] == 0xc2 ||
                                               inst.code[1] == 0xca)))
    end
    return false
end

function is_syscall(inst::Inst, arch::Arch.t, mode::Mode.t)::Bool
    if arch == Arch.X86
        if length(inst.code) == 2 && inst.code == [0xcd, 0x80] 
            return true
        end
    end
    return false
end

#=
| Opcode | Mnemonic      | Description                                                    |
|--------+---------------+----------------------------------------------------------------|
| E8 cw  | CALL rel16    | Call near, relative, displacement relative to next instruction |
| E8 cd  | CALL rel32    | Call near, relative, displacement relative to next instruction |
| FF /2  | CALL r/m16    | Call near, absolute indirect, address given in r/m16           |
| FF /2  | CALL r/m32    | Call near, absolute indirect, address given in r/m32           |
| 9A cd  | CALL ptr16:16 | Call far, absolute, address given in operand                   |
| 9A cp  | CALL ptr16:32 | Call far, absolute, address given in operand                   |
| FF /3  | CALL m16:16   | Call far, absolute indirect, address given in m16:16           |
| FF /3  | CALL m16:32   | Call far, absolute indirect, address given in m16:32           |

=#

function is_direct_call(inst::Inst, arch::Arch.t, mode::Mode.t)::Bool
    if arch == Arch.X86 && mode == Mode.MODE_32
        if length(inst.code) == 5 && inst.code[1] in (0xe8, 0x9a)
            return true
        end
    end
    return false
end


function execute!(emu::Emulator; 
                  chain::Vector{N},
                  registers::Vector{R}=[]) where {N <: Integer, R <: Register}
    load_chain!(emu, chain)
    # TODO: reinitialize writeable memory and registers.
    # Maybe we want to implement the save and restore context methods for Emulator
    # before we do this. Just store the context in a field of the Emulator struct. 
    # Easy peasy.
    
    # First, install some profiling hooks
    code_cb = 
        let profiler::Profiler = Profiler(emu.arch, emu.mode),
            registers::Vector{R} = registers
            function closure(engine::UcHandle, address::UInt64, size::UInt32)
                code::Vector{UInt8} = try
                    mem_read(engine, address = address, size = size)
                catch e
                    @debug e
                    []
                end
                inst = Inst(address = address, code = code)
                push!(profiler._insts, inst)

                # Is this instruction a ret?
                if is_ret(inst, profiler.arch, profiler.mode)
                    # if so, commit the trace and the registers
                    profiler.ret_count += 1
                    profiler.regs = Dict(r => reg_read(emu, r) for r in registers)
                    profiler.insts = vcat(profiler.insts, profiler._insts)
                    profiler._insts = Vector{Inst}()
                elseif (is_syscall(inst, profiler.arch, profiler.mode)
                        || is_direct_call(inst, profiler.arch, profiler.mode))
                    uc_stop!(engine)
                end # end if is_ret
                return nothing
            end # end closure
        end # end let binding
    # end of code_cb definition
    
    code_hook_add!(emu, callback = code_cb)
    exit_code = start!(emu, address = chain[1], until = 0, steps = MAX_STEPS)
    delete_all_hooks!(emu)
    Profile(code_cb.profiler, exit_code)
end # end execute!()

"""
A clean, functional interface to the emulator. This function will
simply map a chain to its execution profile. A list of registers to
read can be supplied as well.
"""
function evaluate(chain::Vector{N},
                  registers::Vector{R})::Profile where {N <: Integer, R <: Register}
    execute!(initialize_emulator(), chain=chain, registers=registers)
end

function evaluate(chain::Vector{N})::Profile where {N <: Integer}
    evaluate(chain, Vector{Register}())
end

end # end module
