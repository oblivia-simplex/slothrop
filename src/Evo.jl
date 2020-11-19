module Evo

using StatsBase
using Distributed
using Random
using LinearAlgebra
using Memoize
using DataFrames
using TOML
using FunctionWrappers: FunctionWrapper
using DistributedArrays

@info "Loading Evo..."

include("Hatchery.jl")
include("Names.jl")
include("../fitness.jl")



export geography,
    tournament!,
    Genome

mutable struct Genome{T}
    chromosome::Vector{T}
    name::String
    generation::Integer
    parents::Vector{String}
    phenome::Union{Missing,Task,Hatchery.Profile}
    fitness::DataFrame
    scalar_fitness::Union{Missing,Float64}
end

function Genome{T}(;chromosome, generation, parents) where {T}
    no_phenome::Union{Missing, Hatchery.Profile} = missing
    Genome(chromosome, 
           Names.rand_name(4), 
           generation, 
           parents,
           no_phenome,
           DataFrame(),
           missing)
end

function random_genome(allele_type; min_len, max_len = min_len, mem=Hatchery.MEMORY)
    Genome{allele_type}(
        # TODO: take a parameter controlling proportions of each Perm, and of
        # purely random numeric values.
        chromosome = [
            convert(allele_type,
                    Hatchery.random_address()) for _ in 1:rand(min_len:max_len)],
        generation = 1,
        parents = Vector{String}(),
    )
end

function mutate!(genome::Genome)

end

# Let's define a maximum genome length now as a constant. Later, we'll want to
# have this as the field of a `Config` struct.

MAX_GENOME_LENGTH = 200

Base.@propagate_inbounds function one_point_crossover(
    parents::Vector{Genome{T}},
)::Vector{Genome{T}} where {T}
    p = rand(1:2)
    mother::Genome, father::Genome = parents[p], parents[(p+1)%2+1]
    mlen = length(mother.chromosome)
    flen = length(father.chromosome)
    mx = rand(1:mlen)
    fx = rand(1:flen)
    fend = min(MAX_GENOME_LENGTH - mx, flen)
    mend = min(MAX_GENOME_LENGTH - fx, mlen)

    c1 = vcat(mother.chromosome[1:mx], father.chromosome[fx:fend])
    c2 = vcat(father.chromosome[1:fx], mother.chromosome[mx:mend])
    @assert length(c1) > 0
    @assert length(c2) > 0
    parent_names = [p.name for p in parents]
    gen = maximum([p.generation for p in parents]) + 1
    g1 = Genome{T}(
        chromosome = c1,
        generation = gen,
        parents = parent_names,
    )
    g2 = Genome{T}(
        chromosome = c2,
        generation = gen,
        parents = parent_names,
    )
    return [g1, g2]
end

#==============================================================================
TODO Consider implementing a `Distributed Array` geography.


This would eliminate the need for a separate migration step, and may present a
cleaner, simpler abstraction layer.

You'd definitely want to make sure that the distance function was set in such
a way that crossing process boundaries was a relatively rare event -- something
that should be precisely tunable. 
===============================================================================#


# We could let the residents of the deme be EITHER futures or genomes.

Base.@kwdef mutable struct Geography{G,N}
    deme #::Array{G,N}
    distance::FunctionWrapper{Float64,Tuple{Float64}}
    toroidal::Bool
    config::Dict{String,Any}
end

function compile_fitness_function(path::String)::FunctionWrapper{Nothing,Tuple{Genome}}
    src = read(path, String)
    exp = Meta.parse(src)
    return eval(exp) |> FunctionWrapper{Nothing,Tuple{Genome}}
end

function geography(
    config;
    allele_type = UInt32, # TODO: infer this from MEMORY
)
    if config ≢ nothing
        if config isa String
            config = TOML.parsefile(config)
        end
        @show config
        if "binary" in keys(config)
            Hatchery.load(config["binary"])
        end
        # Each subprocess should have its own random seed. Redundant otherwise.
        random_seed = config["random_seed"] + myid()
        Random.seed!(random_seed)
        # Get the geography attributes
        geo_conf = config["geography"]
        dims = Tuple(geo_conf["dimensions"])
        distance = (eval(Meta.parse(geo_conf["distance"]))
                    |> FunctionWrapper{Float64,Tuple{Float64}})
        toroidal = geo_conf["toroidal"]

        gen_conf = config["genome"]
        min_len = gen_conf["min_length"]
        max_len = gen_conf["max_length"]
    end
    dimstr = join(string.(dims), "×")
    @info "Generating distributed population of $dimstr ($(prod(dims))) genomes..."
    TYPE = Union{Genome{allele_type}, Task, Future}
    deme = DArray(dims, workers()) do I
        @show I
        d::Array{TYPE,length(dims)} =
            [@async random_genome(allele_type, min_len=min_len, max_len=max_len)
             for _ in zeros(length.(I))]
        @show size(d)
        d
    end
    #deme = [random_genome(allele_type, min_len=min_len, max_len=max_len) 
    #        for _ in zeros(dims...)]

    return Geography{Genome{allele_type},length(dims)}(
        deme = deme,
        distance = distance,
        toroidal = toroidal,
        config = config,
    )
end


function diagonal_size(array)::Float64
    n_dims = length(size(array))
    sum((x - 1)^n_dims for x in Base.size(array))^(1 / n_dims)
end


# Now, it would be nice if distance 'wrapped around' the geography, so that it
# was toroidal instead of prismatic in shape. Otherwise, individuals living in
# corners will have fewer competitors to choose from.

function toroidal_distance(dims, point1, point2)
    point1 = Tuple(point1)
    point2 = Tuple(point2)
    function d(axis, coord1, coord2)
        x = abs(coord1 - coord2)
        min(x, axis - x)
    end
    n_dims = length(dims)
    return sum([
        d(ax, c1, c2)^n_dims for (ax, c1, c2) in zip(dims, point1, point2)
    ])^(1 / n_dims)
end

# @memoize Dict function geo_weights(geo::Geography, origin::Vector{Int})::ProbabilityWeights

#     indices = georegion(geo, region)

#     let dims = size(indices),
#         origin = origin,
#         toroidal = geo.toroidal
#        # max_dist = diagonal_size(indices),

#         function dist(pt)
#             if pt == origin
#                 0.0
#             elseif toroidal
#                 toroidal_distance(dims, origin, pt)
#             else
#                 norm(origin - pt)
#             end
#         end
#         weights = reshape([dist(pt) for pt in indices], prod(size(indices)))
#         maxw = maximum(weights)
#         ProbabilityWeights([geo.distance(1.0 - w / maxw) for w in weights])
#     end
# end

@memoize Dict function distance_weights(indices; origin, distance_λ, toroidal=true)
    dims = size(indices)
    function dist(pt)
        if pt == origin
            0.0
        elseif toroidal
            toroidal_distance(dims, origin, pt)
        else
            norm(origin - pt)
        end
    end
    weights = reshape([dist(pt) for pt in indices], prod(size(indices)))
    maxweight = maximum(weights)
    ProbabilityWeights([distance_λ(1.0 - w / maxweight) for w in weights])
end

function hatch!(genome)
    genome = fetch(genome)
    if ismissing(genome.phenome)
        genome.phenome = Hatchery.evaluate(genome.chromosome)
    end
    genome.fitness = fitness_function(genome.phenome) |> DataFrame
    genome.scalar_fitness = fitness_weighting(genome.fitness)
    @assert !ismissing(genome.scalar_fitness)
    genome
end


function δ_tourney!(deme; tsize, mutation_rate, distance_λ=identity, toroidal)
    habitat = deme[:L]
    # TODO implement migration as relaxation of deme from localpart to global
    # or possibly region
    indices = CartesianIndices(habitat)
    combatant_1 = rand(indices)
    weights = distance_weights(
        indices,
        origin = combatant_1,
        distance_λ = distance_λ,
        toroidal = toroidal)
    combatants = [combatant_1, sample(indices, weights, tsize-1, replace=false)...]

    fetch.(hatch!(habitat[idx]) for idx in combatants)
    # DEBUGGING
#    for idx in combatants
#        g = fetch(habitat[idx])
#        @assert !ismissing(g.scalar_fitness)
#        @show (idx, g.scalar_fitness)
#    end

    # FIXME: I'm still seeing "missing" values here. How is that happening?
    sort!(combatants, rev=true, by = i -> fetch(habitat[i]).scalar_fitness)
    graves = indices[end-1:end]
    parent_indices = indices[1:2]
    parents = [fetch(habitat[i]) for i in parent_indices]
    @show [p.scalar_fitness for p in parents]
    offspring = one_point_crossover(parents)

    for (child, grave) in zip(offspring, graves)
        if rand(Float64) < mutation_rate
            mutate!(fetch(child))
        end
        # Here's the only place where the array itself is mutated:
        habitat[grave] = child
    end
end

function δ_tournament!(geo::Geography)
    tsize = geo.config["geography"]["tournament_size"]
    mutation_rate = geo.config["genome"]["mutation_rate"]
    deme = geo.deme
    distance_λ = geo.distance
    toroidal = geo.toroidal
    @distributed for w in workers()
        δ_tourney!(
            deme,
            tsize = tsize,
            mutation_rate = mutation_rate,
            #distance_λ = distance_λ,
            toroidal = toroidal)
    end
end

end # module Evo
