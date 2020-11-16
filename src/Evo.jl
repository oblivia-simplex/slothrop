module Evo

using StatsBase
using LinearAlgebra
using Memoize
using DataFrames
using TOML
using FunctionWrappers: FunctionWrapper

include("Hatchery.jl")
include("Names.jl")

export geography,
    tournament!,
    Genome

mutable struct Genome{T}
    chromosome::Vector{T}
    name::String
    generation::Integer
    parents::Vector{String}
    phenome::Union{Missing,Hatchery.Profile}
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


Base.@kwdef mutable struct Geography{G,N}
    deme::Array{G,N}
    indices::Vector{Vector{Int64}}
    distance::FunctionWrapper{Float64,Tuple{Float64}}
    toroidal::Bool
    config::Dict{String,Any}
    fitness_function!::FunctionWrapper{Nothing,Tuple{Genome}}
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
        "binary" in keys(config) && Hatchery.load(config["binary"])

        geo_conf = config["geography"]
        fitness_function = compile_fitness_function(geo_conf["fitness_function"])
        dims = geo_conf["dimensions"]
        distance = eval(Meta.parse(geo_conf["distance"])) |> FunctionWrapper{Float64,Tuple{Float64}}
        toroidal = geo_conf["toroidal"]

        gen_conf = config["genome"]
        min_len = gen_conf["min_length"]
        max_len = gen_conf["max_length"]
    end
    index_array = [[Tuple(x)...] for x in CartesianIndices(Tuple([1:d for d in dims]))]
    @info "Generating population of $(length(index_array)) genomes..."
    deme = [random_genome(allele_type, min_len=min_len, max_len=max_len) 
            for _ in index_array]
    indices = reshape(index_array, prod(size(index_array)))

    return Geography{Genome{allele_type},length(dims)}(
        deme = deme,
        indices = indices,
        distance = distance,
        toroidal = toroidal,
        config = config,
        fitness_function! = fitness_function,
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
    function d(axis, coord1, coord2)
        x = abs(coord1 - coord2)
        min(x, axis - x)
    end
    n_dims = length(dims)
    return sum([
        d(ax, c1, c2)^n_dims for (ax, c1, c2) in zip(dims, point1, point2)
    ])^(1 / n_dims)
end

@memoize Dict function geo_weights(geo::Geography; origin::Vector{Int})::ProbabilityWeights
    let dims = size(geo.deme),
        origin = origin,
        max_dist = diagonal_size(geo.indices),
        toroidal = geo.toroidal

        function dist(pt)
            if pt == origin
                0.0
            elseif toroidal
                toroidal_distance(dims, origin, pt)
            else
                norm(origin - pt)
            end
        end
        weights = [dist(pt) for pt in geo.indices]
        maxw = maximum(weights)
        ProbabilityWeights([geo.distance(1.0 - w / maxw) for w in weights])
    end
end


function combatant_indices(geo::Geography, n::Integer)::Vector
    if n == 0
        return []
    end
    first_index = rand(geo.indices)
    if n == 1
        return [first]
    end
    weights = geo_weights(geo, origin = first_index)
    return [first_index, sample(geo.indices, weights, n - 1)...]
end

"""
`ff` is the fitness function. It needs to set two
different fields in the `Genome` struct:

1. the `.fitness` field, which is a `DataFrame`,
   needs to be populated with the various fitness
   attributes, derived from the genome's phenome.

2. the `.scalar_fitness` field should be computed
   in some fashion from the `.fitness` dataframe.

The fitness function should assume that the `.phenome`
of each genome has already been set, and is of type
`Hatchery.Profile`. The fitness should, in general, 
be a function of the phenome structure alone.
"""
function tournament!(geo::Geography)
    tsize = geo.config["geography"]["tournament_size"]
    mutation_rate = geo.config["genome"]["mutation_rate"]
    @assert tsize ≥ 2
    indices = combatant_indices(geo, tsize)
    for i in indices
        g = geo.deme[i...]
        if ismissing(g.phenome)
            g.phenome = Hatchery.evaluate(g.chromosome)
        end
        geo.fitness_function!(g)
    end
    sort!(indices, 
          rev = true,
          by = i -> geo.deme[i...].scalar_fitness)
    parent_indices = indices[1:2]
    dead = indices[end-1:end]
    parents = [geo.deme[i...] for i in parent_indices]
    offspring = one_point_crossover(parents)
    for (child, slot) in zip(offspring, dead)
        if rand(Float64) < mutation_rate
            mutate!(child)
        end
        geo.deme[slot...] = child
    end
end

# TODO: can we write a function that (asynchronously?) performs as many tournaments
# as possible, simultaneously?

end # module Evo
