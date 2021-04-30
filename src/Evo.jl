module Evo

import YAML
using Cockatrice.Geo
using Cockatrice.Config
using Cockatrice.Names
using Cockatrice.Geo: Tracer 
using RecursiveArrayTools

using Distributed
using DistributedArrays


export Creature, Evolution, step!


include("Hatchery.jl")

include("fitness_functions.jl")


Base.@kwdef mutable struct Creature
    chromosome::Vector{UInt32}
    phenotype::Union{Nothing, Hatchery.Profile}
    fitness::Vector{Float64}
    name::String
    generation::Int
    num_offspring::Int = 0
end


Base.isequal(c1::Creature, c2::Creature) = c1.name == c2.name
Base.isless(c1::Creature, c2::Creature) = c1.fitness < c2.fitness


function init_fitness(config::NamedTuple)
  Float64[-Inf for _ in 1:config.d_fitness]
end


function init_fitness(template::Vector)
  Float64[-Inf for _ in template]
end


function Creature(config::NamedTuple)
    Hatchery.load(config.binary_path)
    len = rand(config.genotype.min_len:config.genotype.max_len)
    chromosome = [Hatchery.random_address(Type=UInt32) for _ in 1:len]
    fitness = init_fitness(config)
    Creature(chromosome, fitness)
end


function Creature(chromosome::Vector, fitness::Vector{Float64})
    name = Names.rand_name(4)
    Creature(chromosome=chromosome,
             phenotype=nothing,
             fitness=fitness,
             name=name,
             generation=0)
end


function Creature(chromosome::Vector)
  Creature(chromosome::Vector, Float64[-Inf])
end


function clone_and_mutate(parent::Creature)
    inds = keys(parent.chromosome)
    i = rand(inds)
    chromosome = copy(parent.chromosome)
    chromosome[i] += rand(-16:16)
    offspring = Creature(chromosome)
    offspring.generation = parent.generation + 1
    offspring.name = Names.rand_name(4)
end


function mutate!(creature::Creature)
  inds = keys(creature.chromosome)
  i = rand(inds)
  creature.chromosome[i] += rand(-16:16)
  nothing
end


function mutate_with_probability!(creature::Creature, prob::Float64)
  if rand() < prob
    mutate!(creature)
  end
end


function crossover(mother::Creature, father::Creature)::Vector{Creature}
  mother.num_offspring += 1
  father.num_offspring += 1
  mx = rand(1:length(mother.chromosome))
  fx = rand(1:length(father.chromosome))
  chrom1 = [mother.chromosome[1:mx]; father.chromosome[(fx+1):end]]
  chrom2 = [father.chromosome[1:fx]; mother.chromosome[(mx+1):end]]
  children = Creature.([chrom1, chrom2])
  generation = max(mother.generation, father.generation) + 1
  (c -> c.generation = generation).(children)
  (c -> c.fitness = init_fitness(mother.fitness)).(children)
  children
end


mutable struct Evolution
    config::NamedTuple
    logger
    geo::Geo.Geography{Creature}
    fitness::Function
    iteration::Int
    elites::Vector{Creature}
end


function Evolution(config::NamedTuple; fitness::Function, tracers=[])
    logger = nothing # TODO
    geo = Geo.Geography(Creature, config, tracers=tracers)
    Evolution(config, logger, geo, fitness, 0, [])
end


function Evolution(config::String; fitness::Function, tracers=[]) 
    cfg = Config.parse(config)
    Evolution(cfg, fitness=fitness, tracers=tracers)
end



function preserve_elites!(evo::Evolution)
  pop = sort([vec(evo.geo); evo.elites])
  n_elites = evo.config.population.n_elites
  evo.elites = [deepcopy(pop[end-i]) for i in 0:(n_elites-1)]
end 


# TODO: make the tracer set a field of Geography
# and pass the tracers into the Geography constructor 

function step!(evo::Evolution; crossover=crossover, eval_children=false)
    ranking = Geo.tournament(evo.geo, evo.fitness)
    parents = evo.geo[ranking[end-1:end]]
    children = crossover(parents...)
    if eval_children
      evo.fitness.(children)
    end
    mutate_with_probability!.(children, evo.config.genotype.mutation_rate)
    graves = ranking[1:2]
    evo.geo[graves] = children
    preserve_elites!(evo)
    evo.iteration += 1
    Geo.trace!(evo.geo)
    nothing
end


function evaluate!(evo::Evolution, fitness::Function)
  Geo.evaluate!(evo.geo, fitness)
end


end # end module
