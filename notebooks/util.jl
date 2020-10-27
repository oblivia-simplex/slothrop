### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ 6156c7d8-17ad-11eb-1b13-19319c0aaf8a
md"# Miscellaneous Utility Functions"

# ╔═╡ 6f770742-17ad-11eb-37d2-65d9a63e0bd0
md"## Entropy" 

# ╔═╡ 816c7c20-17ad-11eb-0f0f-1128d1950c89
md"We're going to need a protected log function that maps 0 to 0, rather than -Inf."

# ╔═╡ 970ff8fe-17ad-11eb-2a30-97a825cd6f52
protected_log(n) = n == 0 ? 0 : log(2, n)

# ╔═╡ 751db39e-17ad-11eb-1758-79195681118f
function entropy(vec::Base.ReinterpretArray{UInt8, 1, T})::Float64 where {T}
 	counts = fill(0x00, 256)
          
    for byte in vec
    	counts[byte+1] += 1
    end
           
	filter!(x -> x != 0, counts)
    s = sum(counts)
    l = sum([x * log(2, x) for x in counts])
    return log(2, s) - l / s
end


# ╔═╡ ace6a3e4-17ad-11eb-39d4-cb1762687822
entropy(s::String)::Float64 = entropy(Vector{UInt8}(s))

# ╔═╡ d5e5c698-17ae-11eb-16e6-efe491c751ee
function entropy(v::Vector{T})::Float64 where {T<:Integer} 
	entropy(reinterpret(UInt8, v))
end

# ╔═╡ f0e48e08-17ad-11eb-2460-dd9e91ebfba0
entropy("a")

# ╔═╡ f87987cc-17ad-11eb-10d9-1925c1f2cfa6
entropy("aa")

# ╔═╡ fb0e3ce4-17ad-11eb-0118-0557a20e8136
entropy("ab")

# ╔═╡ 07b74738-17ae-11eb-3566-85cd39778fa3
entropy("AAAAAAAA")

# ╔═╡ 13c1988a-17ae-11eb-1058-1390bf6b8f15
entropy(rand(UInt8, 10_000))

# ╔═╡ b06aea38-17ae-11eb-3f16-53890ac1704c
entropy(rand(UInt64, 1000))

# ╔═╡ Cell order:
# ╟─6156c7d8-17ad-11eb-1b13-19319c0aaf8a
# ╠═6f770742-17ad-11eb-37d2-65d9a63e0bd0
# ╠═816c7c20-17ad-11eb-0f0f-1128d1950c89
# ╠═970ff8fe-17ad-11eb-2a30-97a825cd6f52
# ╠═751db39e-17ad-11eb-1758-79195681118f
# ╠═ace6a3e4-17ad-11eb-39d4-cb1762687822
# ╠═d5e5c698-17ae-11eb-16e6-efe491c751ee
# ╠═f0e48e08-17ad-11eb-2460-dd9e91ebfba0
# ╠═f87987cc-17ad-11eb-10d9-1925c1f2cfa6
# ╠═fb0e3ce4-17ad-11eb-0118-0557a20e8136
# ╠═07b74738-17ae-11eb-3566-85cd39778fa3
# ╠═13c1988a-17ae-11eb-1058-1390bf6b8f15
# ╠═b06aea38-17ae-11eb-3f16-53890ac1704c
