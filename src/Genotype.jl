module Genotype

using Cockatrice.Evo
using Cockatrice.Names

export Creature, mutate!, crossover

include("FF.jl")

Hatchery = FF.Hatchery


Base.@kwdef mutable struct Creature
    chromosome::Vector{UInt32}
    phenotype::Union{Nothing, Hatchery.Profile}
    fitness::Vector{Float64}
    name::String
    generation::Int
    num_offspring::Int = 0
end


function Creature(config::NamedTuple)
    Hatchery.load(config.binary_path)
    len = rand(config.genotype.min_len:config.genotype.max_len)
    chromosome = [Hatchery.random_address(Type=UInt32) for _ in 1:len]
    fitness = Evo.init_fitness(config)
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
  (c -> c.fitness = Evo.init_fitness(mother.fitness)).(children)
  children
end

end # module
