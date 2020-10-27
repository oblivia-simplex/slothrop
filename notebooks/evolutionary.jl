### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ d22a124c-1569-11eb-06eb-7b0f6cc0f3a4
using StatsBase

# ╔═╡ f1787e72-1561-11eb-29ba-ed2da8373109
using Statistics

# ╔═╡ be0cc0f8-1551-11eb-05bc-6b23a6f12449
md"# Genetic Programming in Slothrop"

# ╔═╡ ea3e0420-1551-11eb-349c-93ad13e09472
md"Let's start with the basics. The first thing we need to at least provisionally define is our genome representation. This will just be a stack of integers (for the chromosome itself), and some room for metadata."

# ╔═╡ 18cd70c8-1552-11eb-3a86-d3988999aca0
Base.@kwdef mutable struct Genome{T}
	chromosome::Vector{T}
	name::String
	generation::UInt
	parents::Vector{String}
end

# ╔═╡ 66295346-1552-11eb-2112-191a3a266409
g = Genome{UInt32}(chromosome=rand(UInt32, 8), name="The New Guy", generation=1, parents=[])

# ╔═╡ d6b1538e-1557-11eb-10fd-514c326ffcf8
size(g::Genome) = Base.length(g.chromosome)

# ╔═╡ 5420b148-1558-11eb-1951-7bd6ac8d118b
size(g)

# ╔═╡ 9d56c538-1552-11eb-3047-79c4bc1ad780
md"Now, let's define a single-point crossover operation between these genomes. This has proven to be the most effective form of crossover for this domain, so far, and it's extremely simple to implement."

# ╔═╡ 70a41148-1558-11eb-1e0c-ab1e67665aa6
random_name() = "bob"

# ╔═╡ d0978930-155e-11eb-02fc-4f32f1e9aea7
function random_genome(allele_type, min_len, max_len=min_len)
	Genome{allele_type}(
		chromosome=rand(allele_type, rand(min_len:max_len)),
		name = random_name(),
		generation = 1,
		parents = [],
	)
end

# ╔═╡ c42085da-1552-11eb-2a28-7b2813556840
function one_point_crossover(parents=Vector{Genome})::Vector{Genome}
	p = rand(1:2)
	mother, father = parents[p], parents[(p+1)%2 + 1]
	mx = size(mother) == 1 ? 1 : rand(1:size(mother))
	fx = size(father) == 1 ? 1 : rand(1:size(father))
	c1 = vcat(mother.chromosome[1:mx], father.chromosome[fx:end])
	c2 = vcat(father.chromosome[1:fx], mother.chromosome[mx:end])
	@assert length(c1) > 0
	@assert length(c2) > 0
	parent_names = [p.name for p in parents]
	gen = maximum([p.generation for p in parents])+1
	g1 = Genome(chromosome=c1, name=random_name(), generation=gen, parents=parent_names)
	g2 = Genome(chromosome=c2, name=random_name(), generation=gen, parents=parent_names)
	return [g1, g2]
end

# ╔═╡ 6c302142-1567-11eb-1473-291d9f6a9982


# ╔═╡ fd9dd198-1552-11eb-054b-e9db3bc3a4bf
one_point_crossover([g,g])

# ╔═╡ 8a635570-155e-11eb-03f8-1df98997239c
md"One question we should try to answer right away: is there any innate tendency for chromosomes to increase in length, using this crossover operation? Let's find out."

# ╔═╡ 048e11ac-1553-11eb-351b-95c28ee74bb1
population = [random_genome(UInt32, 1, 100) for i in 1:100_000]

# ╔═╡ 1c986212-1561-11eb-080c-e98179613022
original_population = deepcopy(population)

# ╔═╡ edd1f3f0-1560-11eb-3255-a97144dd52bc
function breed_with_replacement(population)
	i, j = StatsBase.sample(1:length(population), 2, replace=false)
	offspring = one_point_crossover([population[i], population[j]])
	population[i], population[j] = offspring
end
	

# ╔═╡ b926e9aa-1561-11eb-2be2-f9effdc9b3c5
for i in 1:1_000_000
	breed_with_replacement(population)
end

# ╔═╡ 5f69ad62-1561-11eb-0fdf-c5a36643563f
original_mean_size = mean([size(g) for g in original_population])

# ╔═╡ fd07fa74-1561-11eb-1666-9f26efcf8002
new_mean_size = mean([size(g) for g in population])

# ╔═╡ d59b2e3c-1563-11eb-1dcf-af571ab1d216
md"Okay, that's pretty good."

# ╔═╡ Cell order:
# ╟─be0cc0f8-1551-11eb-05bc-6b23a6f12449
# ╟─ea3e0420-1551-11eb-349c-93ad13e09472
# ╠═18cd70c8-1552-11eb-3a86-d3988999aca0
# ╠═66295346-1552-11eb-2112-191a3a266409
# ╠═d6b1538e-1557-11eb-10fd-514c326ffcf8
# ╠═5420b148-1558-11eb-1951-7bd6ac8d118b
# ╠═d0978930-155e-11eb-02fc-4f32f1e9aea7
# ╟─9d56c538-1552-11eb-3047-79c4bc1ad780
# ╠═70a41148-1558-11eb-1e0c-ab1e67665aa6
# ╠═c42085da-1552-11eb-2a28-7b2813556840
# ╠═6c302142-1567-11eb-1473-291d9f6a9982
# ╠═fd9dd198-1552-11eb-054b-e9db3bc3a4bf
# ╟─8a635570-155e-11eb-03f8-1df98997239c
# ╠═048e11ac-1553-11eb-351b-95c28ee74bb1
# ╠═1c986212-1561-11eb-080c-e98179613022
# ╠═d22a124c-1569-11eb-06eb-7b0f6cc0f3a4
# ╠═edd1f3f0-1560-11eb-3255-a97144dd52bc
# ╠═b926e9aa-1561-11eb-2be2-f9effdc9b3c5
# ╠═f1787e72-1561-11eb-29ba-ed2da8373109
# ╠═5f69ad62-1561-11eb-0fdf-c5a36643563f
# ╠═fd07fa74-1561-11eb-1666-9f26efcf8002
# ╠═d59b2e3c-1563-11eb-1dcf-af571ab1d216
