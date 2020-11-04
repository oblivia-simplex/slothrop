module Slothrop
using TOML

include("Evo.jl")

function dispatch(configpath)

    config = TOML.parsefile(configpath)

    geo = Evo.geography(config)

end


end # module
