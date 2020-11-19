module Slothrop

using Distributed
using TOML

@everywhere using Evo

#const IN_SLURM = "SLURM_JOBID" in keys(ENV)
#IN_SLURM && using ClusterManagers

#include("Evo.jl")


function dispatch(config)
    @info "In Slothrop::dispatch"

    if config isa String
        config = TOML.parsefile(config)
    end
    binary_path = config["binary"]
    @everywhere $Evo.Hatchery.load($binary_path)

    geo = Evo.geography(config)

    # let's do a few test tournaments
    n = 1000
    @info "Running $n tournaments..."
    fetch.(Evo.δ_tournament!(geo) for _ in 1:n)
    @info "Finished $n tournaments."

    geo
end


end # module
