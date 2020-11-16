#! /usr/bin/env julia

using Pkg
Pkg.activate(".")
using Slothrop

if length(ARGS) >= 1
    configpath = ARGS[1]
else
    configpath = "./config.toml"
end

geo = Slothrop.dispatch(configpath)

@info "Initialized geography of $(length(geo.deme)) individuals."
