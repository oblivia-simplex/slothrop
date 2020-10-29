module Evo

using StatsBase
using LinearAlgebra
using Memoize

Base.@kwdef mutable struct Genome{T}
    chromosome::Vector{T}
    name::String
    generation::UInt
    parents::Vector{String}
end

random_name() = "Unimplemented"

function random_genome(allele_type, min_len, max_len = min_len)
    Genome{allele_type}(
        chromosome = rand(allele_type, rand(min_len:max_len)),
        name = random_name(),
        generation = 1,
        parents = [],
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
    g1 = Genome(
        chromosome = c1,
        name = random_name(),
        generation = gen,
        parents = parent_names,
    )
    g2 = Genome(
        chromosome = c2,
        name = random_name(),
        generation = gen,
        parents = parent_names,
    )
    return [g1, g2]
end




Base.@kwdef mutable struct Geography{G,N}
    deme::Array{G,N}
    indices::Vector{Vector{Int64}}
    scaling::Function
    toroidal::Bool
end

function geography(;
    dims = [100, 100],
    min_len = 1,
    max_len = 100,
    allele_type = UInt32,
    scaling = identity,
    toroidal = true,
)
    index_array = [[Tuple(x)...] for x in CartesianIndices(Tuple([1:d for d in dims]))]
    deme = [random_genome(allele_type, min_len, max_len) for _ in index_array]
    indices = reshape(index_array, prod(size(index_array)))

    return Geography{Genome{allele_type},length(dims)}(
        deme = deme,
        indices = indices,
        scaling = scaling,
        toroidal = toroidal,
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
        ProbabilityWeights([geo.scaling(1.0 - w / maxw) for w in weights])
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


function tournament!(geo::Geography; tsize::Integer = 4, fitness_fn = _ -> rand(Float64))
    @assert tsize ≥ 2
    indices = combatant_indices(geo, tsize)
    sort(indices, by = i -> fitness_fn(geo.deme[i]))
    parent_indices = indices[1:2]
    dead = indices[end-1:end]
    parents = [geo.deme[i...] for i in parent_indices]
    offspring = one_point_crossover(parents)
    for (child, slot) in zip(offspring, dead)
        geo.deme[slot...] = child
    end
end





end # module Evo
