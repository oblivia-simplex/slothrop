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
include("./util/Rfetch.jl")

rfetch = Rfetch.rfetch

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
    xp::Int
end

function Genome{T}(;chromosome, generation, parents) where {T}
    no_phenome::Union{Missing, Hatchery.Profile} = missing
    Genome(chromosome, 
           Names.rand_name(4), 
           generation, 
           parents,
           no_phenome,
           DataFrame(),
           missing,
           0)
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

function mutate(genome::Genome)::Genome
    @debug "Mutating $(genome.name)"
    genome
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

    deme = DArray(dims, workers()) do I
        d::Array{Union{Genome{allele_type}, Task, Future},length(dims)} =
            [@async random_genome(allele_type, min_len=min_len, max_len=max_len)
             for _ in zeros(length.(I))]
        d
    end

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

zeromissing(m::Missing) = 0.0
zeromissing(x) = x

function choose_migrant(deme, pid; elitist=true)
    @spawnat pid begin
        # ignore unactualized individuals
        fit(g::Future) = 0.0
        fit(g::Union{Task,Genome}) = rfetch(g).scalar_fitness |> zeromissing
        if elitist
            fitnesses = map(fit, deme[:L])
            weights = ProbabilityWeights(reshape(fitnesses, prod(size(deme[:L]))))
            if iszero(weights)
                @info "Migration weights are all zero in deme $pid"
                index = sample(CartesianIndices(deme[:L]))
            else
                index = sample(CartesianIndices(deme[:L]), weights)
            end
        else
            index = sample(CartesianIndices(deme[:L]))
        end
        (index, deme[:L][index])
    end
end

# this is a purely random migration protocol.
# we might want to experiment with a more elitist protocol
function migrate!(geo)
    deme = geo.deme
    δ₁, δ₂ = sample(CartesianIndices(procs(deme)),
                    2, replace=false)
    pid₁, pid₂ = procs(deme)[δ₁], procs(deme)[δ₂]

    #@time slot₁, migrant₁ = choose_migrant(deme, pid₁, elitist=true) |> rfetch
    #slot₂, migrant₂ = choose_migrant(deme, pid₂, elitist=true) |> rfetch
    areas = [collect(deme.indices[δ]) for δ in (δ₁, δ₂)]
    
    slot₁, slot₂ = [CartesianIndex((rand.(I) - first.(I)).+1...) for I in areas]
    @info "Migrating $(Tuple(slot₁)) in deme $pid₁ and $(Tuple(slot₂)) in deme $pid₂"
    migrant₁ = @spawnat pid₁ deme[:L][slot₁]
    migrant₂ = @spawnat pid₂ deme[:L][slot₂]
    

    @spawnat pid₁ deme[:L][slot₁] = migrant₂
    @spawnat pid₂ deme[:L][slot₂] = migrant₁
end


function hatch(genome)
    genome = rfetch(genome)
    genome.xp += 1
    if ismissing(genome.phenome)
        genome.phenome = Hatchery.evaluate(genome.chromosome)
    end
    genome.fitness = fitness_function(genome.phenome) |> DataFrame
    genome.scalar_fitness = fitness_weighting(genome.fitness)
    @debug "$(genome.name) has fitness $(genome.scalar_fitness)"
    @assert !ismissing(genome.scalar_fitness)
    genome
end


function δ_tourney!(deme; tsize, mutation_rate, distance_λ=x -> x^4, toroidal)
    @debug "In δ_tourney!"
    indices = CartesianIndices(deme[:L])
    combatant₁ = rand(indices)
    weights = distance_weights(
        indices,
        origin = combatant₁,
        distance_λ = distance_λ,
        toroidal = toroidal)
    combatants = []
    tries = 0

    combatants = [combatant₁]
    while length(combatants) < tsize
        tries += 1
        c = sample(indices, weights)
        if !(c in combatants)
            push!(combatants, c)
        end
    end

    if tries > 2*tsize
        @debug "took $tries tries to get $tsize unique combatants"
    end
    #for idx in combatants
        # TODO: figure out why we can get a deadlock here, if async
    #    deme[:L][idx] = hatch(deme[:L][idx])
    #end
    for (idx, g) in asyncmap(i -> (i, hatch(deme[:L][i])), combatants)
        deme[:L][idx] = g
    end

    sort!(combatants, rev=true, by = i -> rfetch(deme[:L][i]).scalar_fitness)
    graves = combatants[end-1:end]
    parents = [rfetch(deme[:L][i]) for i in indices[1:2]]
    offspring = one_point_crossover(parents)

    for (child, grave) in zip(offspring, graves)
        if rand(Float64) < mutation_rate
            child = mutate(rfetch(child))
        end
        # Here's the only place where the array itself is mutated:
        @debug "[$(myid())] child: $(child.name) of $(child.parents)"
        deme[:L][grave] = child
    end
end

function tournament!(geo::Geography)
    tsize = geo.config["geography"]["tournament_size"]
    migration_rate = geo.config["geography"]["migration_rate"]
    mutation_rate = geo.config["genome"]["mutation_rate"]
    deme = geo.deme
    toroidal = geo.toroidal
    # One potential issue with this setup is that it's always going to be
    # slowed to the speed of the slowest processor involved.
    # It might be wise to loosen this up a little, and avoid requiring each
    # processor to run in lockstep.
    @distributed for w in workers()
        δ_tourney!(
            deme,
            tsize = tsize,
            mutation_rate = mutation_rate,
            toroidal = toroidal)
    end
    if rand(Float64) < migration_rate
        migrate!(geo)
    end
end

end # module Evo
