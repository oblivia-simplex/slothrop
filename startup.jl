@info "Loading ~/.julia/config/startup.jl..."
using Distributed
@everywhere push!(LOAD_PATH, ".")
@everywhere push!(LOAD_PATH, "src/")

using Pkg
Pkg.instantiate()
@everywhere (using Pkg; Pkg.activate("."))

banner = raw"""
 ____  _       _   _                     
/ ___|| | ___ | |_| |__  _ __ ___  _ __  
\___ \| |/ _ \| __| '_ \| '__/ _ \| '_ \ 
 ___) | | (_) | |_| | | | | | (_) | |_) |
|____/|_|\___/ \__|_| |_|_|  \___/| .__/ 
Return-Oriented Program Evolution |_|    
"""

println(banner)

#Pkg.activate(".")

#using Slothrop
