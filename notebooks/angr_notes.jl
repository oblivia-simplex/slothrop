### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ cc0ad7da-1277-11eb-1791-cf17908059e8
using PyCall

# ╔═╡ 445238f0-127d-11eb-30f5-3f8f33fd2620
using Unicorn

# ╔═╡ 66127efe-1277-11eb-0def-2f7513f2854a
md"# Loading a Binary into Unicorn with Angr"

# ╔═╡ a4289270-1277-11eb-13f0-ad30c5dc7e56
md"We're going to be using the Python framework, `angr`, here, so the first thing we'll need to do is load `PyCall`."

# ╔═╡ cf895be8-1277-11eb-1193-81d6b2ff3a44
angr = pyimport("angr")

# ╔═╡ 5427c122-12e7-11eb-3af7-3d6cf499f634
md"We'll make some use of `angr`'s ROP library, too, later on. So let's import that now, before we build any `angr` objects."

# ╔═╡ ed6d9d4e-12e6-11eb-1367-6720cf920dee
angrop = pyimport("angrop")

# ╔═╡ d7aa0b6a-1277-11eb-1e39-5f68451df161
md"Let's load a binary."

# ╔═╡ c252dfe2-1279-11eb-1f6b-410ff44c410c
path = "../binaries/X86/MODE_32/sshd"

# ╔═╡ 73d772a6-12e7-11eb-307c-634907ef130d
proj = angr.Project(path)

# ╔═╡ 555e8c02-1278-11eb-1de0-b5a2da577ae0
loaded = proj.loader

# ╔═╡ 76f92958-12e9-11eb-36f3-8bb5e9daaccc
md"All we want, right now, are the ELF objects."

# ╔═╡ b4759d44-12ea-11eb-2b9b-59f39d8901a8
elves = loaded.all_elf_objects

# ╔═╡ e534b5d2-12ea-11eb-072e-b981fe1779d0
segs = vcat([[s for s in obj.segments] for obj in elves]...)

# ╔═╡ 8c893806-127a-11eb-20fd-4d87c4ad172d
mem = loaded.memory

# ╔═╡ 36d0bd7c-127c-11eb-3c0c-f7d8a7ab0d2a
Base.@kwdef mutable struct Segment
	vaddr::UInt64
	perms::Perm.t
	data::Vector{UInt8}
end

# ╔═╡ 9fd155b2-127d-11eb-098d-87a4beea9b9c
function perms_of_seg(seg)
	perm = Perm.NONE
	seg.is_readable   && (perm |= Perm.READ)
	seg.is_writable   && (perm |= Perm.WRITE)
	seg.is_executable && (perm |= Perm.EXEC)
	return perm
end

# ╔═╡ 6c6a71aa-127c-11eb-34c4-b934da53b0a6
segments = [Segment(vaddr=s.vaddr, perms=perms_of_seg(s), data=Vector{UInt8}(mem.load(s.min_addr+1, s.memsize))) for s in segs]

# ╔═╡ 7ae28c8e-127e-11eb-2d2e-297864aac4fc
md"Unicorn requires all mapped memory to be 0x1000-byte aligned, so we'll need an address aligning function here."

# ╔═╡ c889f6c8-127e-11eb-0bc3-f9939caf2d9b
PAGE_SIZE = 0x1000

# ╔═╡ 8e2b107c-127e-11eb-1dd8-6bb6846ea74a
PAGE_BITS = Int(log(2, PAGE_SIZE))

# ╔═╡ a8e60354-127e-11eb-33b2-356b2cd03980
# align(n::UInt64) = (n + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1)
align(n::Integer)::Integer = (n >> PAGE_BITS) << PAGE_BITS

# ╔═╡ e709d462-127e-11eb-1c06-e7328f076012
@assert *([align(s.vaddr) % PAGE_SIZE == 0 for s in segments]...)

# ╔═╡ ce8962ee-127f-11eb-2bd7-5b89514c4119
[s.vaddr - align(s.vaddr) for s in segments]

# ╔═╡ 100b96e2-1280-11eb-052b-4fc92f24554a
function pad!(s::Segment)
	dif = s.vaddr - align(s.vaddr)
	@assert dif >= 0
	if dif > 0
		s.data = vcat(zeros(UInt8, dif), s.data)
		s.vaddr = align(s.vaddr)
	end
	# now make sure the size is aligned
	size = length(s.data)
	dif2 = size - align(size)
	@assert dif2 >= 0
	if dif2 > 0
		comp = PAGE_SIZE - (size % PAGE_SIZE)
		@show comp, size
		s.data = vcat(s.data, zeros(UInt8, comp))
		@show length(s.data) - size
	end
	@assert length(s.data) % PAGE_SIZE == 0
	return
end

# ╔═╡ 582db586-1280-11eb-12f4-0dd9d7507bf5
for segment in segments
	pad!(segment)
end

# ╔═╡ 79917e24-1280-11eb-2927-4d46afcacbb2
segments

# ╔═╡ ad952658-1280-11eb-3626-2b91ac9a7d40
[UInt(length(s.data)) for s in segments]

# ╔═╡ b5d85da8-1280-11eb-0785-0b22e0947972
[length(s.data) - align(length(s.data)) for s in segments]	

# ╔═╡ bff6437c-1280-11eb-35e3-87907fa1d25d
[Pair(s.vaddr, s.vaddr + length(s.data)) for s in segments]

# ╔═╡ 34bb5520-12e6-11eb-3f43-2d3272760c05
md"Let's add a region for the stack."

# ╔═╡ 8f67622a-12e6-11eb-2aa0-e9d90b23207a
STACK_ADDR = maximum(s.vaddr + length(s.data) for s in segments)

# ╔═╡ c7e2e4bc-12e6-11eb-1d10-7dfbce7ca255
STACK_SIZE = 0x1000

# ╔═╡ 3a0ad4b0-12e6-11eb-3203-0964b35422f0
push!(segments, Segment(vaddr=UInt64(STACK_ADDR), perms=Perm.READ | Perm.WRITE, data=zeros(UInt8, STACK_SIZE)))

# ╔═╡ ea776416-12f1-11eb-1a1a-e77f02fd08b1
md"## Using Angr to Determine an Initial State"

# ╔═╡ f439f338-12f1-11eb-3edc-77b4153c9bd1
md"We could do a lot more with Angr, I think. Why not use it to figure out an initial state for our search? Better yet, we could, in certain cases, use it to find an initial _weird_ state!"

# ╔═╡ 0ff1ee6e-12f2-11eb-14bf-e15866ae8db8
entry_state = proj.factory.entry_state()

# ╔═╡ 1bdad420-12f2-11eb-1d94-ddfe28aa2bf8
md"Note: we're going to follow this [Angr tutorial](https://docs.angr.io/core-concepts/toplevel), here..."

# ╔═╡ 4cb02502-12f2-11eb-2113-3fecf7e457d9
simgr = proj.factory.simulation_manager(entry_state)

# ╔═╡ 56ba3448-12f2-11eb-1460-77062910e7ac
md"Let's take a first step into the execution."

# ╔═╡ b2c62a86-12f2-11eb-14d3-7f155c0191a5
simgr.step()

# ╔═╡ bd056702-12f2-11eb-0b77-ed8ad5c2d5eb
initial_register_map = Dict([(r, simgr.active[1].regs[r]) for r in pybuiltin(:dir)(simgr.active[1].regs)])

# ╔═╡ 7451bdca-12f3-11eb-0dcb-811c7da1a194
md"Where is the stack pointer at the beginning of all this? Where's the instruction pointer?"

# ╔═╡ 84f8fc74-12f3-11eb-28ed-31f444fd097e
esp = initial_register_map["esp"]

# ╔═╡ 8f75355c-12f3-11eb-3947-8de0b09f5289
eip = initial_register_map["eip"]

# ╔═╡ 2deb656c-12f4-11eb-3c59-a52d50ee3d8b
md"Let's take a look at our memory map, again."

# ╔═╡ ae9000f0-12f3-11eb-3735-679a33b36352
[(Pair(s.vaddr, s.vaddr + length(s.data)), UInt32(length(s.data))) for s in segments]

# ╔═╡ dde35e10-12f3-11eb-13a0-196c4f6a77d4
md"Okay, so the instruction pointer is falling squarely within our executable section. So far, so good. But the stack pointer doesn't line up with our hastily allocated stack. This is no surprise -- we didn't really try to get it right, yet. Let's fix that."

# ╔═╡ c1fa36b0-12f3-11eb-37c8-d91f37b57d70


# ╔═╡ 48d9b38e-1283-11eb-2c55-8d4f0c04db2f
md"## Now let's try to map things to the emulator."

# ╔═╡ 528f70d6-12eb-11eb-22ee-db8cab3d12d8
md"We're copying `segments` to another variable here just to coax the notebook into executing the cells in the right order."

# ╔═╡ 0fe785d6-12fd-11eb-3079-0b2a675360ea
segments

# ╔═╡ 8b41f222-1283-11eb-37d9-a998cc7dafca
emu = begin
	emu = Emulator(Arch.X86, Mode.MODE_32)
	for s in segments
		@show s.perms, s.perms & Perm.WRITE
		if s.perms & Perm.WRITE == Perm.NONE
			println("Using mem_map_array")
			mem_map_array(emu, 
				address = s.vaddr, 
				size = length(s.data), 
				array = s.data, 
				perms = s.perms)
		else
			mem_map(emu, address = s.vaddr, size = length(s.data), perms = s.perms)
			mem_write(emu, address = s.vaddr, bytes = s.data)
		end
	end
	emu
end

# ╔═╡ 4f24c8d0-12fd-11eb-0053-8d7aba701df6
length(emu.array_backed_memory)

# ╔═╡ 139bd6f6-12e8-11eb-3853-3971b31c6c36
mem_regions(emu)

# ╔═╡ 048c1f86-1284-11eb-0ad9-75019a337165
md"## ROP Execution"

# ╔═╡ ec1b834a-12e6-11eb-2638-f371e24b3241
md"Now, suppose we wanted to execute a ROP chain on this system. Let's use `angr`, first, to generate a chain."

# ╔═╡ 735de590-12eb-11eb-1227-772cf4093ff7
ROP_analysis = proj.analyses.ROP()

# ╔═╡ 8685a612-12eb-11eb-287f-174cf1f64f7d
gadgets = begin
	ROP_analysis.find_gadgets(16)
	ROP_analysis.gadgets
end

# ╔═╡ f9af3aa8-12ec-11eb-0160-210e873d7576
chain = ROP_analysis.set_regs(eax=0x1337, ebx=0xdeadbeef)

# ╔═╡ 06582c76-12f5-11eb-31b0-5335780e4999


# ╔═╡ Cell order:
# ╟─66127efe-1277-11eb-0def-2f7513f2854a
# ╟─a4289270-1277-11eb-13f0-ad30c5dc7e56
# ╠═cc0ad7da-1277-11eb-1791-cf17908059e8
# ╠═445238f0-127d-11eb-30f5-3f8f33fd2620
# ╠═cf895be8-1277-11eb-1193-81d6b2ff3a44
# ╟─5427c122-12e7-11eb-3af7-3d6cf499f634
# ╠═ed6d9d4e-12e6-11eb-1367-6720cf920dee
# ╟─d7aa0b6a-1277-11eb-1e39-5f68451df161
# ╠═c252dfe2-1279-11eb-1f6b-410ff44c410c
# ╠═73d772a6-12e7-11eb-307c-634907ef130d
# ╠═555e8c02-1278-11eb-1de0-b5a2da577ae0
# ╟─76f92958-12e9-11eb-36f3-8bb5e9daaccc
# ╠═b4759d44-12ea-11eb-2b9b-59f39d8901a8
# ╟─e534b5d2-12ea-11eb-072e-b981fe1779d0
# ╠═8c893806-127a-11eb-20fd-4d87c4ad172d
# ╠═36d0bd7c-127c-11eb-3c0c-f7d8a7ab0d2a
# ╠═9fd155b2-127d-11eb-098d-87a4beea9b9c
# ╠═6c6a71aa-127c-11eb-34c4-b934da53b0a6
# ╟─7ae28c8e-127e-11eb-2d2e-297864aac4fc
# ╠═c889f6c8-127e-11eb-0bc3-f9939caf2d9b
# ╠═8e2b107c-127e-11eb-1dd8-6bb6846ea74a
# ╠═a8e60354-127e-11eb-33b2-356b2cd03980
# ╠═e709d462-127e-11eb-1c06-e7328f076012
# ╠═ce8962ee-127f-11eb-2bd7-5b89514c4119
# ╠═100b96e2-1280-11eb-052b-4fc92f24554a
# ╠═582db586-1280-11eb-12f4-0dd9d7507bf5
# ╠═79917e24-1280-11eb-2927-4d46afcacbb2
# ╠═ad952658-1280-11eb-3626-2b91ac9a7d40
# ╠═b5d85da8-1280-11eb-0785-0b22e0947972
# ╠═bff6437c-1280-11eb-35e3-87907fa1d25d
# ╟─34bb5520-12e6-11eb-3f43-2d3272760c05
# ╠═8f67622a-12e6-11eb-2aa0-e9d90b23207a
# ╠═c7e2e4bc-12e6-11eb-1d10-7dfbce7ca255
# ╠═3a0ad4b0-12e6-11eb-3203-0964b35422f0
# ╟─ea776416-12f1-11eb-1a1a-e77f02fd08b1
# ╟─f439f338-12f1-11eb-3edc-77b4153c9bd1
# ╠═0ff1ee6e-12f2-11eb-14bf-e15866ae8db8
# ╟─1bdad420-12f2-11eb-1d94-ddfe28aa2bf8
# ╠═4cb02502-12f2-11eb-2113-3fecf7e457d9
# ╟─56ba3448-12f2-11eb-1460-77062910e7ac
# ╠═b2c62a86-12f2-11eb-14d3-7f155c0191a5
# ╠═bd056702-12f2-11eb-0b77-ed8ad5c2d5eb
# ╟─7451bdca-12f3-11eb-0dcb-811c7da1a194
# ╠═84f8fc74-12f3-11eb-28ed-31f444fd097e
# ╠═8f75355c-12f3-11eb-3947-8de0b09f5289
# ╟─2deb656c-12f4-11eb-3c59-a52d50ee3d8b
# ╠═ae9000f0-12f3-11eb-3735-679a33b36352
# ╟─dde35e10-12f3-11eb-13a0-196c4f6a77d4
# ╠═c1fa36b0-12f3-11eb-37c8-d91f37b57d70
# ╟─48d9b38e-1283-11eb-2c55-8d4f0c04db2f
# ╟─528f70d6-12eb-11eb-22ee-db8cab3d12d8
# ╠═0fe785d6-12fd-11eb-3079-0b2a675360ea
# ╠═8b41f222-1283-11eb-37d9-a998cc7dafca
# ╠═4f24c8d0-12fd-11eb-0053-8d7aba701df6
# ╠═139bd6f6-12e8-11eb-3853-3971b31c6c36
# ╟─048c1f86-1284-11eb-0ad9-75019a337165
# ╟─ec1b834a-12e6-11eb-2638-f371e24b3241
# ╠═735de590-12eb-11eb-1227-772cf4093ff7
# ╠═8685a612-12eb-11eb-287f-174cf1f64f7d
# ╠═f9af3aa8-12ec-11eb-0160-210e873d7576
# ╠═06582c76-12f5-11eb-31b0-5335780e4999
