module Entropy

export entropy

"""
Calculate the bytewise Shannon entropy of a vector of bits type data.
"""
function entropy(vec::Base.ReinterpretArray{UInt8, 1, T})::Float64 where {T}
    counts = fill(0x00, 256)
          
    for byte in vec
    	counts[byte+1] += 1
    end
           
	filter!(x -> x != 0, counts)
    s = sum(counts)
    l = sum(x * log(2, x) for x in counts)
    return log(2, s) - l / s
end

entropy(s::String)::Float64 = entropy(Vector{UInt8}(s))

function entropy(v::Vector{T})::Float64 where {T<:Integer} 
	entropy(reinterpret(UInt8, v))
end


end # end module
