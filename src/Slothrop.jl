module Slothrop

using Distributed
using TOML

const IN_SLURM = "SLURM_JOBID" in keys(ENV)

IN_SLURM && using ClusterManagers

include("Evo.jl")


function dispatch(configpath)

    config = TOML.parsefile(configpath)

    if IN_SLURM
        pids = addprocs_slurm(parse(Int, ENV["SLURM_NTASKS"]))
        print("\n")
    else
        pids = addprocs()
    end

    # Set up a pier for migration

    geo = Evo.geography(config)

    # let's do a few test tournaments
    n = 1000
    @info "Running $n tournaments..."
    for i in 1:n
        Evo.tournament!(geo)
    end
    @info "Finished $n tournaments."

    geo
end


end # module
