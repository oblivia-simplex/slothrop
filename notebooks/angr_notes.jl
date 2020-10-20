### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ cc0ad7da-1277-11eb-1791-cf17908059e8
using PyCall

# ╔═╡ 445238f0-127d-11eb-30f5-3f8f33fd2620
using Unicorn

# ╔═╡ 2ae4ccc6-1312-11eb-1b4f-2559ac117cab
using Printf

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

# ╔═╡ 8213b9a0-1306-11eb-11ff-0ddae3c60b03
md"It'll be nice to have a disassembler around, too."

# ╔═╡ 8836398e-1306-11eb-2cd3-2b4618da36c0
capstone = pyimport("capstone")

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
segments = [Segment(vaddr=s.vaddr, perms=perms_of_seg(s), data=Vector{UInt8}(mem.load(s.min_addr, s.memsize))) for s in segs]

# ╔═╡ 595e1ff8-1308-11eb-3df0-db67468223ec
[UInt32(length(s.data)) for s in segments]

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

# ╔═╡ afc5954c-1308-11eb-334e-dfcb30aacb1d
our_segments = deepcopy(segments)

# ╔═╡ 582db586-1280-11eb-12f4-0dd9d7507bf5
for segment in our_segments
	pad!(segment)
end

# ╔═╡ 79917e24-1280-11eb-2927-4d46afcacbb2
our_segments, [UInt32(length(s.data)) for s in our_segments]

# ╔═╡ bff6437c-1280-11eb-35e3-87907fa1d25d
[Pair(s.vaddr, s.vaddr + length(s.data)) for s in our_segments]

# ╔═╡ 34bb5520-12e6-11eb-3f43-2d3272760c05
md"Let's add a region for the stack."

# ╔═╡ 8f67622a-12e6-11eb-2aa0-e9d90b23207a
STACK_ADDR = maximum(s.vaddr + length(s.data) for s in our_segments)

# ╔═╡ c7e2e4bc-12e6-11eb-1d10-7dfbce7ca255
STACK_SIZE = 0x1000

# ╔═╡ 7451bdca-12f3-11eb-0dcb-811c7da1a194
md"Where is the stack pointer at the beginning of all this? Where's the instruction pointer?"

# ╔═╡ 2deb656c-12f4-11eb-3c59-a52d50ee3d8b
md"Let's take a look at our memory map, again."

# ╔═╡ ae9000f0-12f3-11eb-3735-679a33b36352
[(Pair(s.vaddr, s.vaddr + length(s.data)), UInt32(length(s.data))) for s in segments]

# ╔═╡ c1fa36b0-12f3-11eb-37c8-d91f37b57d70


# ╔═╡ 48d9b38e-1283-11eb-2c55-8d4f0c04db2f
md"## Now let's try to map things to the emulator."

# ╔═╡ 528f70d6-12eb-11eb-22ee-db8cab3d12d8
md"We're copying `segments` to another variable here just to coax the notebook into executing the cells in the right order."

# ╔═╡ d53a57ce-1310-11eb-3d2f-d7c9516e4ce4
push!(our_segments, Segment(vaddr=UInt64(STACK_ADDR), perms=Perm.READ | Perm.WRITE, data=zeros(UInt8, STACK_SIZE)))

# ╔═╡ 0fe785d6-12fd-11eb-3079-0b2a675360ea
our_segments

# ╔═╡ 8b41f222-1283-11eb-37d9-a998cc7dafca
emu = begin
	emu = Emulator(Arch.X86, Mode.MODE_32)
	for s in our_segments
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
pchain = ROP_analysis.set_regs(eax=0x1337, ebx=0xdeadbeef)

# ╔═╡ 88a6dcec-1307-11eb-0c48-ddbb917df77d
pchain.print_payload_code()

# ╔═╡ 06582c76-12f5-11eb-31b0-5335780e4999
payload = Vector{UInt8}(pchain.payload_str())

# ╔═╡ 0e0fe3bc-1306-11eb-284f-7bbfb5c51a7f
chain = reinterpret(UInt32, payload)

# ╔═╡ 338de76a-1306-11eb-0940-5b4aa91e3e6f
md"In Slothrop, we'll mostly be dealing with chains of UInt32 or UInt64 values, depending on architecture, which we'll want to pack before we send them to the emulator. Packing, in Julia, can be done with the zero-cost operation `reinterpret()`, going in a direction opposite to the one you see here, from Vector{UInt32} to Vector{UInt8}."

# ╔═╡ 28230a22-1310-11eb-1661-db2fc998e50f
md"### Loading the ROP Chain into the Unicorn Emulator"

# ╔═╡ 320aa8a4-1310-11eb-3076-41dcb0654abf
md"First, let's choose an address for the stack. (Perhaps, eventually, we'll use `angr` to _infer_ the stack address at the time of attack.) For now, let's set it to `STACK_ADDR + (STACK_SIZE / 2)` == $(UInt32(STACK_ADDR + (STACK_SIZE / 2)))"

# ╔═╡ 82365abe-1310-11eb-0e2f-0536ae88d630
STACK_POINTER = UInt32(STACK_ADDR + STACK_SIZE / 2)

# ╔═╡ a5764f16-1310-11eb-187d-8f16b68d713c
WORD_SIZE = 4

# ╔═╡ 2de5db20-1311-11eb-263c-610aa6654254
md"Now we copy the payload into stack memory."

# ╔═╡ b1bb1810-1310-11eb-0bde-093fcd0ba63f
mem_write(emu, address = STACK_POINTER, bytes = payload)

# ╔═╡ 0afe62ce-1311-11eb-2f48-399e8e6f27a1
md"Then, pop the first word of the chain into the instruction pointer."

# ╔═╡ c244e2d8-1310-11eb-2f7c-cbb1756c2e8f
reg_write(emu, register = X86.Register.EIP, value = chain[1]) # not necessary

# ╔═╡ 02882d96-1311-11eb-1fe5-2b96edfb8aec
reg_write(emu, register = X86.Register.ESP, value = STACK_POINTER + WORD_SIZE)

# ╔═╡ 26817e3c-1311-11eb-3b4f-e322b93d74fc
md"Let's install a disassembly hook so we can see what's going on."

# ╔═╡ c52bff76-1311-11eb-2e63-95dbfe27b7d1
callback = 
	let dis = Vector{String}()
	sizehint!(dis, 64)
	function closure(engine::UcHandle, address::UInt64, size::UInt32)
		code::Vector{UInt8} = mem_read(engine, address = address, size = size)
		cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)	
		d = cs.disasm(code, address)
		for inst in d
			s = @sprintf "0x%x:\t%s\t%s\n" inst.address inst.mnemonic inst.op_str
			push!(dis, s)
			@show s
		end
	end
end

# ╔═╡ 75348172-1312-11eb-1080-8132da73ab2d
hh = code_hook_add(emu, callback = callback)

# ╔═╡ 9243df24-1312-11eb-106d-6d45eded343d
md"We'll be able to access this enclosed list using dot notation, which is a real treat: `callback.dis` == $((callback.dis))."

# ╔═╡ 43eae270-1313-11eb-00d3-4f369d33cb85
start(emu, begin_addr = chain[1], until_addr = 0, steps = 16)

# ╔═╡ 2a93aa72-1316-11eb-0768-2f307620e877
md"#### Did it work?"

# ╔═╡ dcfb9644-1315-11eb-2f1d-3b2744781029
eax = reg_read(emu, X86.Register.EAX)

# ╔═╡ 070e4b5e-1316-11eb-2fee-bbe96e21af0a
ebx = reg_read(emu, X86.Register.EBX)

# ╔═╡ a1693c42-1317-11eb-1e61-810cba6be9a7
md"""#### $(eax == 0x1337 && ebx == 0xdeadbeef ? "Yes, it did!" :  "No, it did not work." )
"""

# ╔═╡ 390649b6-1316-11eb-08b6-59750c7b44ee
md"Now, let's take a look at the disassembly trace."

# ╔═╡ 435ca81a-1316-11eb-306f-e75df10ea7b5
Markdown.parse("""```
$(join(callback.dis))
```""")

# ╔═╡ 6655e098-1316-11eb-3e8c-456fcf76cea9
md"This trace remains accessible in `callback.dis`. Enclosed variables, in Julia, can be accessed through dot notation, like struct fields."

# ╔═╡ ea776416-12f1-11eb-1a1a-e77f02fd08b1
md"# Using Angr to Determine an Initial State"

# ╔═╡ f439f338-12f1-11eb-3edc-77b4153c9bd1
md"We could do a lot more with Angr, I think. Why not use it to figure out an initial state for our search? Better yet, we could, in certain cases, use it to find an initial _weird_ state!"

# ╔═╡ 1bdad420-12f2-11eb-1d94-ddfe28aa2bf8
md"Note: we're going to follow this [Angr tutorial](https://docs.angr.io/core-concepts/toplevel), here..."

# ╔═╡ 0ff1ee6e-12f2-11eb-14bf-e15866ae8db8
entry_state = proj.factory.entry_state()

# ╔═╡ 4cb02502-12f2-11eb-2113-3fecf7e457d9
simgr = proj.factory.simulation_manager(entry_state)

# ╔═╡ 56ba3448-12f2-11eb-1460-77062910e7ac
md"Let's take a first step into the execution."

# ╔═╡ b2c62a86-12f2-11eb-14d3-7f155c0191a5
simgr.step()

# ╔═╡ bd056702-12f2-11eb-0b77-ed8ad5c2d5eb
initial_register_map = Dict([(r, simgr.active[1].regs[r]) for r in pybuiltin(:dir)(simgr.active[1].regs)])

# ╔═╡ 84f8fc74-12f3-11eb-28ed-31f444fd097e
esp = initial_register_map["esp"]

# ╔═╡ 8f75355c-12f3-11eb-3947-8de0b09f5289
eip = initial_register_map["eip"]

# ╔═╡ dde35e10-12f3-11eb-13a0-196c4f6a77d4
md"Okay, so the instruction pointer is falling squarely within our executable section. So far, so good. But the stack pointer doesn't line up with our hastily allocated stack. This is no surprise -- we didn't really try to get it right, yet. Let's fix that."

# ╔═╡ 4872cfdc-1316-11eb-195a-134d4dcf6dcd


# ╔═╡ Cell order:
# ╟─66127efe-1277-11eb-0def-2f7513f2854a
# ╟─a4289270-1277-11eb-13f0-ad30c5dc7e56
# ╠═cc0ad7da-1277-11eb-1791-cf17908059e8
# ╠═445238f0-127d-11eb-30f5-3f8f33fd2620
# ╠═2ae4ccc6-1312-11eb-1b4f-2559ac117cab
# ╠═cf895be8-1277-11eb-1193-81d6b2ff3a44
# ╟─5427c122-12e7-11eb-3af7-3d6cf499f634
# ╠═ed6d9d4e-12e6-11eb-1367-6720cf920dee
# ╟─8213b9a0-1306-11eb-11ff-0ddae3c60b03
# ╠═8836398e-1306-11eb-2cd3-2b4618da36c0
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
# ╠═595e1ff8-1308-11eb-3df0-db67468223ec
# ╟─7ae28c8e-127e-11eb-2d2e-297864aac4fc
# ╠═c889f6c8-127e-11eb-0bc3-f9939caf2d9b
# ╠═8e2b107c-127e-11eb-1dd8-6bb6846ea74a
# ╠═a8e60354-127e-11eb-33b2-356b2cd03980
# ╠═e709d462-127e-11eb-1c06-e7328f076012
# ╠═ce8962ee-127f-11eb-2bd7-5b89514c4119
# ╠═100b96e2-1280-11eb-052b-4fc92f24554a
# ╠═afc5954c-1308-11eb-334e-dfcb30aacb1d
# ╠═582db586-1280-11eb-12f4-0dd9d7507bf5
# ╠═79917e24-1280-11eb-2927-4d46afcacbb2
# ╠═bff6437c-1280-11eb-35e3-87907fa1d25d
# ╟─34bb5520-12e6-11eb-3f43-2d3272760c05
# ╠═8f67622a-12e6-11eb-2aa0-e9d90b23207a
# ╠═c7e2e4bc-12e6-11eb-1d10-7dfbce7ca255
# ╟─7451bdca-12f3-11eb-0dcb-811c7da1a194
# ╟─2deb656c-12f4-11eb-3c59-a52d50ee3d8b
# ╠═ae9000f0-12f3-11eb-3735-679a33b36352
# ╠═c1fa36b0-12f3-11eb-37c8-d91f37b57d70
# ╟─48d9b38e-1283-11eb-2c55-8d4f0c04db2f
# ╟─528f70d6-12eb-11eb-22ee-db8cab3d12d8
# ╠═d53a57ce-1310-11eb-3d2f-d7c9516e4ce4
# ╠═0fe785d6-12fd-11eb-3079-0b2a675360ea
# ╠═8b41f222-1283-11eb-37d9-a998cc7dafca
# ╠═4f24c8d0-12fd-11eb-0053-8d7aba701df6
# ╠═139bd6f6-12e8-11eb-3853-3971b31c6c36
# ╟─048c1f86-1284-11eb-0ad9-75019a337165
# ╟─ec1b834a-12e6-11eb-2638-f371e24b3241
# ╠═735de590-12eb-11eb-1227-772cf4093ff7
# ╠═8685a612-12eb-11eb-287f-174cf1f64f7d
# ╠═f9af3aa8-12ec-11eb-0160-210e873d7576
# ╠═88a6dcec-1307-11eb-0c48-ddbb917df77d
# ╠═06582c76-12f5-11eb-31b0-5335780e4999
# ╠═0e0fe3bc-1306-11eb-284f-7bbfb5c51a7f
# ╟─338de76a-1306-11eb-0940-5b4aa91e3e6f
# ╟─28230a22-1310-11eb-1661-db2fc998e50f
# ╟─320aa8a4-1310-11eb-3076-41dcb0654abf
# ╠═82365abe-1310-11eb-0e2f-0536ae88d630
# ╠═a5764f16-1310-11eb-187d-8f16b68d713c
# ╟─2de5db20-1311-11eb-263c-610aa6654254
# ╠═b1bb1810-1310-11eb-0bde-093fcd0ba63f
# ╟─0afe62ce-1311-11eb-2f48-399e8e6f27a1
# ╠═c244e2d8-1310-11eb-2f7c-cbb1756c2e8f
# ╠═02882d96-1311-11eb-1fe5-2b96edfb8aec
# ╟─26817e3c-1311-11eb-3b4f-e322b93d74fc
# ╠═c52bff76-1311-11eb-2e63-95dbfe27b7d1
# ╠═75348172-1312-11eb-1080-8132da73ab2d
# ╠═9243df24-1312-11eb-106d-6d45eded343d
# ╠═43eae270-1313-11eb-00d3-4f369d33cb85
# ╟─2a93aa72-1316-11eb-0768-2f307620e877
# ╠═dcfb9644-1315-11eb-2f1d-3b2744781029
# ╠═070e4b5e-1316-11eb-2fee-bbe96e21af0a
# ╟─a1693c42-1317-11eb-1e61-810cba6be9a7
# ╟─390649b6-1316-11eb-08b6-59750c7b44ee
# ╠═435ca81a-1316-11eb-306f-e75df10ea7b5
# ╟─6655e098-1316-11eb-3e8c-456fcf76cea9
# ╟─ea776416-12f1-11eb-1a1a-e77f02fd08b1
# ╟─f439f338-12f1-11eb-3edc-77b4153c9bd1
# ╟─1bdad420-12f2-11eb-1d94-ddfe28aa2bf8
# ╠═0ff1ee6e-12f2-11eb-14bf-e15866ae8db8
# ╠═4cb02502-12f2-11eb-2113-3fecf7e457d9
# ╟─56ba3448-12f2-11eb-1460-77062910e7ac
# ╠═b2c62a86-12f2-11eb-14d3-7f155c0191a5
# ╠═bd056702-12f2-11eb-0b77-ed8ad5c2d5eb
# ╠═84f8fc74-12f3-11eb-28ed-31f444fd097e
# ╠═8f75355c-12f3-11eb-3947-8de0b09f5289
# ╟─dde35e10-12f3-11eb-13a0-196c4f6a77d4
# ╠═4872cfdc-1316-11eb-195a-134d4dcf6dcd
