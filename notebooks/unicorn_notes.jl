### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ 7acfdcc2-124e-11eb-37b3-0d6df96ff3ba
using Unicorn

# ╔═╡ 5d5bfd96-1240-11eb-2dae-5b3b1bd63a1d
using PyCall

# ╔═╡ 2f3fbeba-1243-11eb-2592-eb8c0de8f351
using Printf

# ╔═╡ c604c88c-1236-11eb-230c-652ef7f6e877
md"# Using the Unicorn Emulator"

# ╔═╡ 7fd189dc-124e-11eb-1f89-57d0dad3c20c
md"This package supplies a Julia wrapper for the [Unicorn Emulation Library](http://unicorn-engine.org). To get started with the library, simply import it with 

```
Pkg.add(url=\"https://github.com/oblivia-simplex/unicorn-jl\")
``` 

and then, in the REPL, enter"

# ╔═╡ a81adbee-1237-11eb-3b17-e7b19eca3f6c
md"An emulator can be initialized by passing an `Arch.t` and a `Mode.t` variant to the `Emulator` constructor, like so:"

# ╔═╡ 94cb2ac8-1237-11eb-1103-9105aee682db
emu = Emulator(Arch.X86, Mode.MODE_64)

# ╔═╡ efe04b04-124a-11eb-2ebd-59e517550c84
md"## Mapping and Preparing Memory"

# ╔═╡ 3f8525de-1238-11eb-3fb1-8f58db34efe0
md"The next step is typically to map a region of memory to the emulator. This can be done in one of two ways: we may provide the emulator with `address`, `perms` and `size` parameters, and let it allocate the memory itself, or we may pre-allocate an array, and pass it to the emulator. This second option allows us to reuse the same memory across numerous emulators (which we can do safely enough so long as the memory is marked as read-only), and retain direct access to that region of memory.

Note that emulator mapped memory _must_ be page-aligned (i.e., evenly divisible by 0x1000)."

# ╔═╡ ae47a758-1238-11eb-2e96-bd13b350077a
text_memory, stack_memory = fill(0x00, 0x2000), fill(0x00, 0x1000)

# ╔═╡ 1ae6694e-1239-11eb-3456-e192b83a369a
try
	Unicorn.mem_map_array(emu, address = 0x1000, size = 0x2000, perms = Perm.READ | Perm.WRITE | Perm.EXEC, array = text_memory)
catch e
	if e == Unicorn.UcException(Unicorn.UcError.MAP)
		md"This method will throw an $e exception if run more than once in a row with the same parameters. This is because the emulator will refuse to map a region that has already been mapped."
	else
		throw(e)
	end
end

# ╔═╡ f6abd068-123c-11eb-39ef-6741c9490212
try
	Unicorn.mem_map_array(emu, address = 0x40_000, size = 0x1000, perms = Perm.WRITE | Perm.READ, array = stack_memory)
catch e
	md"Here, we can expect to see a '$(e)' if the cell is run more than once."
end

# ╔═╡ c9506264-1239-11eb-1893-111dfdcb27f9
md"Now let's load some code into the emulator.

```
49 c7 c6 08 00 04 00      mov $0x00040000, %r14
4c 89 f4                  mov %r14, %rsp
ba ef be ad de            mov $0xcafebeef, %edx
52                        push %rdx
```
"


# ╔═╡ 89cd300a-123d-11eb-39c4-e36a77c343da
code = [
	0x49, 0xc7, 0xc6, 0x08, 0x00, 0x04, 0x00,
	0x4c, 0x89, 0xf4,
	0xba, 0xef, 0xbe, 0xfe, 0xca,
	0x52
]

# ╔═╡ adec2540-123d-11eb-0670-43225377f55d
mem_write(emu, address = 0x1000, bytes = code)

# ╔═╡ 312648de-123f-11eb-0470-dbeb996846b0
md"Let's check to see if `text_memory` has been written to."

# ╔═╡ cb5c5c1c-123d-11eb-1984-4b6b44325dc0
text_memory

# ╔═╡ da11b2fa-123f-11eb-3ed2-37eef0af9065
md"We can check the mapped memory regions at any time with `mem_regions()`."

# ╔═╡ 03a11fb4-1240-11eb-3f0f-25c203e32b2e
mem_regions(emu)

# ╔═╡ 12d5e160-1240-11eb-20ff-17aa2dbf65e7
md"## Hooking Callbacks into Emulation Events

Much of the power of the Unicorn library comes from its ability to hook specific emulation events and call user-defined callbacks. Let's set a callback to disassemble instructions as they're executed. For this, we'll use the Capstone disassembly library, via its Python bindings, using `PyCall`." 

# ╔═╡ 6cd718a0-1240-11eb-2ebe-55a898a6046d
capstone = pyimport("capstone")

# ╔═╡ 269dd940-1241-11eb-1514-833b022bc7ee
cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# ╔═╡ 86e3866a-1241-11eb-31a0-73c9896dcc62
md"The best way to get information back out of the emulator is by using closures as callbacks. Here, we're going to use a closure to push disassembly results back into the environment from which the emulation is dispatched."

# ╔═╡ c3c24ec6-1242-11eb-1dab-376e5c0c123d
disassembly = Vector{String}()

# ╔═╡ 0bef5d6c-1246-11eb-2bdb-1d0577b8cf11
addresses = Vector{UInt64}()


# ╔═╡ 9b5a1ecc-1241-11eb-018c-85d41e8f03a2
callback = 
	let disassembly::Vector{String} = disassembly
	let addresses::Vector{UInt64} = addresses
	sizehint!(disassembly, 1024)
	sizehint!(addresses, 1024)
	function closure(handle::UcHandle, address::UInt64, size::UInt32)
		push!(addresses, address)
		bytes = mem_read(handle, address = address, size = size)
		for inst in cs.disasm(bytes, address)
			dis = @sprintf "0x%x: %s\t%s\n" inst.address inst.mnemonic inst.op_str
			push!(disassembly, dis)
		end
	end
end
end

# ╔═╡ ae2dcc4c-124d-11eb-2ad3-81cf2159ef47
md"Note that we need to be _extremely_ careful here, or else we risk memory corruption. The size and memory layout of any data structures that will be mutated by the callback functions should be fixed before execution begins."

# ╔═╡ 6f0c67a8-1243-11eb-2bbd-dd9a8624ff41
hook_handle = code_hook_add(emu, begin_addr=0x1000, until_addr=0x2000, callback=callback)

# ╔═╡ 6b51d77e-1243-11eb-337d-373da2f79e9b
md"Now we're ready to launch the emulation."

# ╔═╡ f3c05f7c-1243-11eb-38d4-cf3ff655ee21
start(emu, begin_addr=0x1000, until_addr=0x2000, steps=4)

# ╔═╡ 78030b16-1248-11eb-3823-f3b341e9fad2
md"The `disassembly` vector should now contain the output of the capstone disassembler that we ran in our code hook callback. Let's take a look."

# ╔═╡ 0f483e54-1244-11eb-317d-93c6eb3eee43
Markdown.parse("### Results of the Disassembly Trace 
	```
	
$(*(disassembly...))
	
```")

# ╔═╡ fae9ecb0-124c-11eb-16be-81bcc30ed002
disassembly

# ╔═╡ 68f63150-1248-11eb-2955-6dbf52c20776
md"And the `addresses` vector should contain all of the addresses executed by the emulator."

# ╔═╡ a00ff164-1248-11eb-1162-d7fc60cb3773
addresses

# ╔═╡ a63442aa-1248-11eb-19a3-4fb88a3fed26
md"Finally, the `stack_memory` array should contain the word `0xdeadbeef`, which our emulated x86_64 code pushed to the stack."

# ╔═╡ c120fc84-1248-11eb-33ef-7b6f9f5a4a8d
reinterpret(UInt32, stack_memory[1:4])[1]

# ╔═╡ e02eff0e-1248-11eb-0953-4b2dd5ced19e
md"Let's look at the stack pointer in our emulated CPU."

# ╔═╡ eaced3ee-1248-11eb-3ac7-4f15b682768b
reg_read(emu, X86.Register.RSP)

# ╔═╡ a0f065e2-124a-11eb-37e3-bb1589537dd7
md"We can also read emulation memory through the Unicorn API, with the `mem_read()` method."

# ╔═╡ b6004086-124a-11eb-2c09-b3192cebcbbf
reinterpret(UInt32, mem_read(emu, address=0x40_000, size=4))[1]

# ╔═╡ e81ea82c-124d-11eb-2c9e-591d7deebb7e
md"Finally, we can removed the hooked callback with `hook_del()`:"

# ╔═╡ e0cf5328-124d-11eb-3e7c-f7521fb9373e
hook_del(emu, hook_handle)

# ╔═╡ Cell order:
# ╟─c604c88c-1236-11eb-230c-652ef7f6e877
# ╟─7fd189dc-124e-11eb-1f89-57d0dad3c20c
# ╠═7acfdcc2-124e-11eb-37b3-0d6df96ff3ba
# ╟─a81adbee-1237-11eb-3b17-e7b19eca3f6c
# ╠═94cb2ac8-1237-11eb-1103-9105aee682db
# ╟─efe04b04-124a-11eb-2ebd-59e517550c84
# ╟─3f8525de-1238-11eb-3fb1-8f58db34efe0
# ╠═ae47a758-1238-11eb-2e96-bd13b350077a
# ╠═1ae6694e-1239-11eb-3456-e192b83a369a
# ╠═f6abd068-123c-11eb-39ef-6741c9490212
# ╟─c9506264-1239-11eb-1893-111dfdcb27f9
# ╠═89cd300a-123d-11eb-39c4-e36a77c343da
# ╠═adec2540-123d-11eb-0670-43225377f55d
# ╟─312648de-123f-11eb-0470-dbeb996846b0
# ╠═cb5c5c1c-123d-11eb-1984-4b6b44325dc0
# ╟─da11b2fa-123f-11eb-3ed2-37eef0af9065
# ╠═03a11fb4-1240-11eb-3f0f-25c203e32b2e
# ╟─12d5e160-1240-11eb-20ff-17aa2dbf65e7
# ╠═5d5bfd96-1240-11eb-2dae-5b3b1bd63a1d
# ╠═6cd718a0-1240-11eb-2ebe-55a898a6046d
# ╠═269dd940-1241-11eb-1514-833b022bc7ee
# ╟─86e3866a-1241-11eb-31a0-73c9896dcc62
# ╠═c3c24ec6-1242-11eb-1dab-376e5c0c123d
# ╠═0bef5d6c-1246-11eb-2bdb-1d0577b8cf11
# ╠═2f3fbeba-1243-11eb-2592-eb8c0de8f351
# ╠═9b5a1ecc-1241-11eb-018c-85d41e8f03a2
# ╟─ae2dcc4c-124d-11eb-2ad3-81cf2159ef47
# ╠═6f0c67a8-1243-11eb-2bbd-dd9a8624ff41
# ╟─6b51d77e-1243-11eb-337d-373da2f79e9b
# ╠═f3c05f7c-1243-11eb-38d4-cf3ff655ee21
# ╟─78030b16-1248-11eb-3823-f3b341e9fad2
# ╠═0f483e54-1244-11eb-317d-93c6eb3eee43
# ╠═fae9ecb0-124c-11eb-16be-81bcc30ed002
# ╟─68f63150-1248-11eb-2955-6dbf52c20776
# ╠═a00ff164-1248-11eb-1162-d7fc60cb3773
# ╟─a63442aa-1248-11eb-19a3-4fb88a3fed26
# ╠═c120fc84-1248-11eb-33ef-7b6f9f5a4a8d
# ╟─e02eff0e-1248-11eb-0953-4b2dd5ced19e
# ╠═eaced3ee-1248-11eb-3ac7-4f15b682768b
# ╟─a0f065e2-124a-11eb-37e3-bb1589537dd7
# ╠═b6004086-124a-11eb-2c09-b3192cebcbbf
# ╟─e81ea82c-124d-11eb-2c9e-591d7deebb7e
# ╠═e0cf5328-124d-11eb-3e7c-f7521fb9373e
