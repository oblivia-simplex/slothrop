module Hatchery

using PyCall
using Unicorn
using Printf

angr = pyimport("angr")
capstone = pyimport("capstone")

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
end

function get_stack(mem::MemoryImage)
    filter(s -> s.label == :stack, mem.segs)
end

function load(path)
    global MEMORY

    if typeof(MEMORY) ≡ MemoryImage && MEMORY.path == path
        return MEMORY
    end

    proj = angr.Project(path)
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

    MEMORY = MemoryImage(segs = segments, path = path)

end

function initialize_emulator(memory::Union{MemoryImage,Nothing} = nothing)::Emulator
    global MEMORY
    if memory ≡ nothing
        memory = MEMORY
    end

    emu = Emulator(Arch.X86, Mode.MODE_32)
    for s in memory.segs
        if s.perms & Perm.WRITE == Perm.NONE
            mem_map_array(
                emu,
                address = s.address,
                size = length(s.data),
                array = s.data,
                perms = s.perms,
            )
        else
            mem_map(emu, address = s.address, size = length(s.data), perms = s.perms)
            mem_write!(emu, address = s.address, bytes = s.data)
        end
    end
    emu
end

function load_chain!(emu::Emulator, chain::Vector{Integer})
    sp = UInt64(get_stack(MEMORY).address + STACK_SIZE / 2)
    mem_write!(emu, address = sp, bytes = reinterpret(UInt8, chain))
    reg_write!(emu, register = stack_pointer(emu), value = sp + word_size(emu))

end

end # end module
