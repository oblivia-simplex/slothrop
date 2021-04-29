using StatsBase
using Memoize
using Distributed
# These two dependencies are optional, and are only used by the visualization
# functions, that are, in turn, only used for debugging purposes.
using Images
using ImageInTerminal


Base.@kwdef mutable struct Geography{G<:Individual,N}
    deme::Array{G,N}
    indices::CartesianIndices
    toroidal::Bool
    locality::Int
    config::NamedTuple
end


function Geography(
    constructor,
    config,
)

    dimstr = join(string.(config.population.size), "×")
    @info "Generating distributed population of $dimstr ($(prod(config.population.size))) genomes..."

    indices = CartesianIndices(Tuple(config.population.size))
    deme = [constructor(config) for _ in indices]

    return Geography(
        deme = deme,
        indices = indices,
        locality = config.population.locality,
        toroidal = config.population.toroidal,
        config = config,
    )
end


function diagonal_size(array)::Float64
    n_dims = length(size(array))
    sum((x - 1)^n_dims for x in Base.size(array))^(1 / n_dims)
end


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


@memoize Dict function distance_weights(indices; origin, locality, toroidal=true)
    distance_λ = x -> x^locality
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


function distance_weights(geo::Geography, origin)
    distance_weights(geo.indices,
                     origin=origin,
                     locality=geo.locality,
                     toroidal=geo.toroidal)
end


function see_weights(geo::Geography, origin)
    Gray.(reshape(distance_weights(geo, origin), size(geo.deme)))
end


function choose_combatants(geo::Geography, tsize; origin=nothing)
    @assert tsize > 1
    origin = origin === nothing ? rand(geo.indices) : origin
    weights = distance_weights(geo, origin)
    sample(geo.indices, weights, tsize, replace=false)
end

function see_combatants(geo::Geography, tsize; origin=nothing)
    combatants = choose_combatants(geo, tsize, origin=origin)
    cells = [c ∈ combatants ? 1.0 : 0.0 for c in geo.indices]
    Gray.(cells)
end

##
# Defining a few Base methods for Geography, so that it can be
# transparently swapped in where Arrays are used.
##

Base.sort(geo::Geography) = Base.sort(geo.deme)

Base.length(geo::Geography) = Base.length(geo.deme)

Base.getindex(geo::Geography, i) = Base.getindex(geo.deme, i)
Base.setindex!(geo::Geography, g, i) = Base.setindex!(geo.deme, g, i)

Base.size(geo::Geography) = Base.size(geo.deme)
Base.size(geo::Geography, dim) = Base.size(geo.deme, dim)

Base.IteratorSize(geo::Geography) = Base.IteratorSize(geo.deme)
Base.iterate(geo::Geography) = Base.iterate(geo.deme)
Base.iterate(geo::Geography, state) = Base.iterate(geo.deme, state)

Base.keys(geo::Geography) = geo.indices

Base.vec(geo::Geography) = Base.vec(geo.deme
