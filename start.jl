#! /usr/bin/env bash
# -*- mode: julia -*-
#=
[ -n "$SLOTHROP_PROCS" ] || SLOTHROP_PROCS=`nproc`

export DIR="$(cd $(dirname ${BASH_SOURCE[0]}); pwd)"

exec julia --color=yes \
           --procs=${SLOTHROP_PROCS} \
           --startup-file=no \
           "${BASH_SOURCE[0]}" \
           -- "$@"
=#

@show ARGS
@show ENV["DIR"]

using Distributed

@everywhere push!(LOAD_PATH, $(ENV["DIR"]))
@everywhere push!(LOAD_PATH, $(ENV["DIR"] * "/src"))

@info "Running Slothrop on $(nprocs()) processes..."
@everywhere using Pkg
@everywhere Pkg.activate(".")
@everywhere using TOML
@everywhere using Slothrop

if length(ARGS) >= 1
    configpath = ARGS[1]
else
    configpath = "./config.toml"
end

# KLUDGE 
config = TOML.parsefile(configpath)
@everywhere ENV["SLOTHROP_BINARY_PATH"] = $(config["binary"])

geo = Slothrop.dispatch(configpath)

@info "Initialized geography of $(length(geo.deme)) individuals."
