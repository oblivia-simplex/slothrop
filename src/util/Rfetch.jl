module Rfetch

export rfetch

using Distributed

# Recursive fetching is pretty handy.
rfetch(x::Union{Task,Future}) = rfetch(fetch(x))
rfetch(x) = fetch(x)

end
