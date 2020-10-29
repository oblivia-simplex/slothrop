### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ f1787e72-1561-11eb-29ba-ed2da8373109
using Statistics

# ╔═╡ d22a124c-1569-11eb-06eb-7b0f6cc0f3a4
using StatsBase

# ╔═╡ 430a9668-194e-11eb-3ad4-0702391d3d3b
using LinearAlgebra

# ╔═╡ ea64af28-1950-11eb-04fa-4199a7ad6be2
using Memoize

# ╔═╡ 6b3ecca4-1952-11eb-3aa1-39f46ab8f8f2
using Plots

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

# ╔═╡ 729ee498-1934-11eb-1166-574ea3c7ca6c
md"Let's define a maximum genome length now as a constant. Later, we'll want to have this as the field of a `Config` struct."

# ╔═╡ 558bf45a-1933-11eb-30e9-6b58cf5209b9
MAX_GENOME_LENGTH = 200

# ╔═╡ c42085da-1552-11eb-2a28-7b2813556840
Base.@propagate_inbounds function one_point_crossover(parents=Vector{Genome})::Vector{Genome}
	p = rand(1:2)
	mother, father = parents[p], parents[(p+1)%2 + 1]
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
	gen = maximum([p.generation for p in parents])+1
	g1 = Genome(chromosome=c1, name=random_name(), generation=gen, parents=parent_names)
	g2 = Genome(chromosome=c2, name=random_name(), generation=gen, parents=parent_names)
	return [g1, g2]
end

# ╔═╡ 6c302142-1567-11eb-1473-291d9f6a9982


# ╔═╡ fd9dd198-1552-11eb-054b-e9db3bc3a4bf
one_point_crossover([g,g])

# ╔═╡ d59b2e3c-1563-11eb-1dcf-af571ab1d216
md"Okay, that's pretty good."

# ╔═╡ 969f9402-1934-11eb-0160-7f63ce6e4197
md"## Fake Tournaments"

# ╔═╡ 9d5609f0-1934-11eb-38f4-e5c7e8e9a8bb
md"First, we'll need a dummy fitness function."

# ╔═╡ a3884fc2-1934-11eb-1388-6374662de618
fitness_fn(_) = rand(Float64)

# ╔═╡ bc01da00-1934-11eb-0940-dd4410ecca23
md"Now, the familiar tournament function."

# ╔═╡ c62e389a-1934-11eb-0672-b95358cdcaf2

function tournament_β!(population, tsize)
	@assert tsize ≥ 2
	indices = StatsBase.sample(1:length(population), tsize, replace=false)
	# At this point, if we can ensure that every worker has nonoverlapping
	# indices, we can proceed without fear of a race condition. But it gets
	# a bit tricky if we don't have a fork/join on each tournament. This
	# is what we did in ROPER 1.
	sort(indices, by = i -> fitness_fn(population[i]))
	parents = indices[1:2]
	dead = indices[end-1:end]
	offspring = one_point_crossover([population[i...] for i in parents])
	o = 1
	for (child, slot) in zip(offspring, dead)
		population[slot...] = child
	end
end

# ╔═╡ 048e11ac-1553-11eb-351b-95c28ee74bb1
population = [random_genome(UInt32, 1, 100) for i in 1:100_000]

# ╔═╡ 8a635570-155e-11eb-03f8-1df98997239c
md"One question we should try to answer right away: is there any innate tendency for chromosomes to increase in length, using this crossover operation? Let's find out."

# ╔═╡ 3169d630-193a-11eb-3923-f5b5d72775a6
for i in 1:1000
	tournament_β!(population, 4)
end

# ╔═╡ 015ffe98-193e-11eb-0238-25fbdf757409
md"## Less Trivial Geography"

# ╔═╡ 05f2adae-193e-11eb-1497-073687db2ffa
Base.@kwdef mutable struct Geography{G, N}
	deme::Array{G,N}
	indices::Vector{Vector{Int64}}
	scaling::Function
	toroidal::Bool
end

# ╔═╡ 752c12f8-193e-11eb-01f0-adf1e55c343a
function geography(;dims = [100, 100],
		genome_type=UInt32, 
		min_len=1, 
		max_len=100,
		denizen_type=Genome,
		scaling=identity,
		toroidal=true,
	)
	index_array = [[Tuple(x)...] 
		for x in CartesianIndices(Tuple([1:d for d in dims]))]
	if denizen_type ≡ Genome
		deme = [random_genome(UInt32, min_len, max_len) for _ in index_array]
	elseif denizen_type ≡ UInt8
		deme = rand(UInt8, size(index_array)...)
	end
		
	indices = reshape(index_array, prod(size(index_array)))

	return Geography{denizen_type,length(dims)}(
		deme = deme, 
		indices = indices,
		scaling = scaling,
		toroidal = toroidal)
end
	

# ╔═╡ d7d1e7fa-195e-11eb-0533-cdad4239d93f
scale(x) = x ^ 4

# ╔═╡ 981415ac-1945-11eb-03c5-273ec7b5069e
geo = geography(dims = [16, 16], scaling = scale, denizen_type=UInt8); nothing

# ╔═╡ 206d0678-194d-11eb-0a38-05f26e3c3656
function diagonal_size(array)::Float64
	n_dims = length(size(array))
	sum((x-1)^n_dims for x in Base.size(array))^(1/n_dims)
end

# ╔═╡ 96b6f334-194d-11eb-2712-6727dfd8a495
diagonal_size(zeros(100,100))


# ╔═╡ abefa84a-1950-11eb-305a-5f8310270b14
md"The idea here is that we want the probability of being selected as a competitor in a tournament to be proportional to distance from the first combatant chosen."

# ╔═╡ c355398e-1950-11eb-14e5-35ba23625ea3
md"This gives us means of constructing a weighting, but it should really be optimized. It looks like a function that could easily be memoized."

# ╔═╡ be05d9ea-1953-11eb-26af-2bff99c9419a
md"Now, it would be nice if distance 'wrapped around' the geography, so that it was toroidal instead of prismatic in shape. Otherwise, individuals living in corners will have fewer competitors to choose from."

# ╔═╡ 91ea7238-1955-11eb-1546-c531dc9996b1
function toroidal_distance(dims, point1, point2)
	function d(axis, coord1, coord2)
		x = abs(coord1 - coord2)
		min(x, axis - x)
	end
	n_dims = length(dims)
	return sum([d(ax, c1, c2)^n_dims 
			 for (ax, c1, c2) in 
		 	 zip(dims, point1, point2)])^(1/n_dims)
end

# ╔═╡ 6b261fda-194b-11eb-0c57-3f5b509d4078
@memoize Dict function geo_weights(
		geo::Geography;
		origin::Vector{Int})::ProbabilityWeights
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
	ProbabilityWeights([geo.scaling(1.0 - w/maxw) for w in weights])
	end
end
	

# ╔═╡ 080d9722-1951-11eb-11e1-a953b88b5be5
@time all_weightings = [geo_weights(geo, origin=pt) for pt in geo.indices]

# ╔═╡ a08f4b82-1951-11eb-097e-973802eb6a52
@time w = geo_weights(geo, origin=[8,4])

# ╔═╡ 0b857a8a-1950-11eb-0e90-bfc5232e3165
minimum(w), maximum(w)

# ╔═╡ b5004560-1958-11eb-3ff5-9f5307b41164
mean(w)

# ╔═╡ b9a82a92-1958-11eb-1741-2d3b5a007792
std(w)

# ╔═╡ 7fe79cfa-1950-11eb-1ec5-45d4fe85ed6d
@time sample(geo.indices, w, 4, replace=false)

# ╔═╡ 7813b69c-1952-11eb-1aad-fd97b92acff1
function combatant_indices(geo::Geography, n::Integer)::Vector
	if n == 0
		return []
	end
	first_index = rand(geo.indices)
	if n == 1
		return [first]
	end
	weights = geo_weights(geo, origin=first_index)
	return [first_index, sample(geo.indices, weights, n-1)...]
end


# ╔═╡ b9812dc0-1953-11eb-3526-a708031e641b
combatant_indices(geo, 4)

# ╔═╡ 57887c06-1959-11eb-2607-4d3433ce86bb
md"Let's plot this to get a better sense of how this works, and to sanity check things."

# ╔═╡ 64352834-1959-11eb-1223-2d53c66cdbb5
size(w)

# ╔═╡ bd8e318c-1959-11eb-1cca-9190d74cc911
weight2d = reshape(w, 16,16)


# ╔═╡ 4bdb25ee-195f-11eb-2f5e-01915e6c17d4
function plot_geographical_radius(scaling_function, dims=[64,64])
	geo = geography(dims = dims, scaling = scaling_function)
	origin = rand(geo.indices)
	w = geo_weights(geo, origin = origin)
	weight2d = reshape(w, dims...)
	heatmap(weight2d)
end

# ╔═╡ ce3bc53a-1959-11eb-3634-bd86332337a1
plot_geographical_radius(identity)

# ╔═╡ d7da7ce4-1959-11eb-2862-7ba40fcae2f9
md"The simplest way to contract the 'radius' of selection is to increase the exponent on the scaling function. Setting it to `scale(x) = x^2` or `scale(x) = x^4`, for example."

# ╔═╡ 10c3e7b0-1960-11eb-2424-5be77481189c
plot_geographical_radius(x -> x^2)

# ╔═╡ 26fec6a8-1960-11eb-29d0-d344ecf551c7
plot_geographical_radius(x -> x^3)

# ╔═╡ 44c62212-1960-11eb-36b3-112ebe213462
plot_geographical_radius(x -> x^4)

# ╔═╡ 70695932-1960-11eb-0120-bd2fd9cc6774
plot_geographical_radius(tanh)

# ╔═╡ 76f9e64c-1960-11eb-35f9-6d14721d2d21
plot_geographical_radius(x -> tanh(x^2))

# ╔═╡ 81e1ba3a-1960-11eb-0142-cfb217696f84
plot_geographical_radius(x -> tanh(x)^2)

# ╔═╡ 8e61a34c-1960-11eb-2bfd-9f49552d84ed
plot_geographical_radius(x -> tanh(x^4))

# ╔═╡ 9c974360-1960-11eb-18d3-ff6211ee338d
plot_geographical_radius(x -> tanh(x^8))

# ╔═╡ ee6961ee-1960-11eb-2159-b15c13b654e6
plot_geographical_radius(x -> x^16, [256,256])

# ╔═╡ 3a6e64c6-196a-11eb-1d1a-c7e19c9e971c
md"A hard radius can be implemented by using a ternary cutoff expression, like so."

# ╔═╡ 293db5aa-196a-11eb-1930-918249f36aae
plot_geographical_radius(x -> x^8 > 0.3 ? 1.0 : 0.0)

# ╔═╡ 7259e18c-1974-11eb-3345-579a0a799042
waves(x) = max(0, sin(x^8 * 6π))

# ╔═╡ 6c21d460-1973-11eb-13af-c3d2b10b16d8
plot_geographical_radius(waves, [300,300])

# ╔═╡ a0b8a888-1960-11eb-377a-51e381f3bd22
md"What happens if we try to do this in higher dimension? We can't quite do the heatmap trick to visualize it, but it should work out well enough."

# ╔═╡ b5baebda-1968-11eb-1b0a-3d8f113e55b0
geo3d_dims = [100,100,100]

# ╔═╡ 68650278-1961-11eb-2c0e-ff85a4bdcd0d
geo3d = geography(dims = geo3d_dims, scaling = x -> x^32, denizen_type = UInt8); nothing


# ╔═╡ 9ed51b2a-1961-11eb-2565-5540bdc7a968
combs = combatant_indices(geo3d, 4)

# ╔═╡ 81fa4310-1961-11eb-13a9-89b0e6ebe9bf
w3d = geo_weights(geo3d, origin = combs[1])

# ╔═╡ 7e378a2a-1962-11eb-2507-ef1961e5f5a4
w3d_arr = reshape(w3d, geo3d_dims...); nothing

# ╔═╡ 98b63bbc-1962-11eb-3fb0-ffffb3fb47da
heatmap(view(w3d_arr, :, :, 1))

# ╔═╡ ea06a006-1962-11eb-37e7-05e29b0ad0d8
heatmap(view(w3d_arr, :, :, 50))

# ╔═╡ feb7abce-1962-11eb-0d4a-db7f4167dee5
heatmap(view(w3d_arr, 50, :, :))

# ╔═╡ 2ff1c89c-1967-11eb-0e32-d721d7149536
combatants = combatant_indices(geo3d, 1000)

# ╔═╡ 270fdada-1968-11eb-3fdf-396e0da9aab2
function coords(combatants)
	([c[1] for c in combatants],
		[c[2] for c in combatants],
		[c[3] for c in combatants])
end

# ╔═╡ 145cb5fc-1968-11eb-2abc-19352aadd45d
scatter3d(coords(combatants)...)

# ╔═╡ 1936db8e-1968-11eb-0078-af74996040c5
geo1d = geography(dims = [1000], scaling = x -> tanh(x^8))

# ╔═╡ fc030822-196b-11eb-15c1-13ff9d45e23e
comb1d = vcat(combatant_indices(geo1d, 1000)...)

# ╔═╡ cc4914ee-196d-11eb-3d00-eda117a451d4
w1d = geo_weights(geo1d, origin=[comb1d[1]])

# ╔═╡ 7305f74e-196d-11eb-2b4e-95c24a81a15f
histogram(comb1d, bins=range(minimum(comb1d), stop=maximum(comb1d), length=100))

# ╔═╡ da599c0c-196d-11eb-128c-b96f052f7b4f
plot(w1d)

# ╔═╡ 6bbbdd72-196e-11eb-0446-934abb82f41c
md"By specifying a hard step function for scaling, and restricting ourselves to one dimension, we can reproduce the *Trivial Geography* data structure used in Berbalang."

# ╔═╡ 1c709af0-196e-11eb-1d51-9106d29ec60c
geo1d_hard = geography(dims = [1000], scaling = x -> x > 0.9 ? 1.0 : 0.0)

# ╔═╡ 3a044936-196e-11eb-03e1-650c6f80e4ad
comb1d_hard = vcat(combatant_indices(geo1d_hard, 1000)...)

# ╔═╡ 5f06411c-196e-11eb-1d52-4b3824b4e542
histogram(comb1d_hard, bins=range(minimum(comb1d_hard), stop=maximum(comb1d_hard), length=100))

# ╔═╡ 915269e8-196e-11eb-0d9c-1b7d57fc3ea8
w1d_hard = geo_weights(geo1d_hard, origin=[comb1d_hard[1]])

# ╔═╡ af93d00e-196e-11eb-1cf9-31490dc68c04
plot(w1d_hard)

# ╔═╡ 7e9c446a-1987-11eb-2376-2f158aaeafac
md"## Geography and Tournaments"

# ╔═╡ 87042cbc-1987-11eb-24aa-edca0ff78613
function tournament!(
		geo::Geography; 
		tsize::Integer = 4, 
		fitness_fn = _ -> rand(Float64))
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


# ╔═╡ Cell order:
# ╟─be0cc0f8-1551-11eb-05bc-6b23a6f12449
# ╠═f1787e72-1561-11eb-29ba-ed2da8373109
# ╠═d22a124c-1569-11eb-06eb-7b0f6cc0f3a4
# ╠═430a9668-194e-11eb-3ad4-0702391d3d3b
# ╠═ea64af28-1950-11eb-04fa-4199a7ad6be2
# ╠═6b3ecca4-1952-11eb-3aa1-39f46ab8f8f2
# ╟─ea3e0420-1551-11eb-349c-93ad13e09472
# ╠═18cd70c8-1552-11eb-3a86-d3988999aca0
# ╠═66295346-1552-11eb-2112-191a3a266409
# ╠═d0978930-155e-11eb-02fc-4f32f1e9aea7
# ╟─9d56c538-1552-11eb-3047-79c4bc1ad780
# ╠═70a41148-1558-11eb-1e0c-ab1e67665aa6
# ╟─729ee498-1934-11eb-1166-574ea3c7ca6c
# ╠═558bf45a-1933-11eb-30e9-6b58cf5209b9
# ╠═c42085da-1552-11eb-2a28-7b2813556840
# ╠═6c302142-1567-11eb-1473-291d9f6a9982
# ╠═fd9dd198-1552-11eb-054b-e9db3bc3a4bf
# ╟─d59b2e3c-1563-11eb-1dcf-af571ab1d216
# ╟─969f9402-1934-11eb-0160-7f63ce6e4197
# ╠═9d5609f0-1934-11eb-38f4-e5c7e8e9a8bb
# ╠═a3884fc2-1934-11eb-1388-6374662de618
# ╠═bc01da00-1934-11eb-0940-dd4410ecca23
# ╠═c62e389a-1934-11eb-0672-b95358cdcaf2
# ╠═048e11ac-1553-11eb-351b-95c28ee74bb1
# ╟─8a635570-155e-11eb-03f8-1df98997239c
# ╠═3169d630-193a-11eb-3923-f5b5d72775a6
# ╠═015ffe98-193e-11eb-0238-25fbdf757409
# ╠═05f2adae-193e-11eb-1497-073687db2ffa
# ╠═752c12f8-193e-11eb-01f0-adf1e55c343a
# ╠═d7d1e7fa-195e-11eb-0533-cdad4239d93f
# ╠═981415ac-1945-11eb-03c5-273ec7b5069e
# ╠═206d0678-194d-11eb-0a38-05f26e3c3656
# ╠═96b6f334-194d-11eb-2712-6727dfd8a495
# ╟─abefa84a-1950-11eb-305a-5f8310270b14
# ╟─c355398e-1950-11eb-14e5-35ba23625ea3
# ╟─be05d9ea-1953-11eb-26af-2bff99c9419a
# ╠═91ea7238-1955-11eb-1546-c531dc9996b1
# ╠═6b261fda-194b-11eb-0c57-3f5b509d4078
# ╠═080d9722-1951-11eb-11e1-a953b88b5be5
# ╠═a08f4b82-1951-11eb-097e-973802eb6a52
# ╠═0b857a8a-1950-11eb-0e90-bfc5232e3165
# ╠═b5004560-1958-11eb-3ff5-9f5307b41164
# ╠═b9a82a92-1958-11eb-1741-2d3b5a007792
# ╠═7fe79cfa-1950-11eb-1ec5-45d4fe85ed6d
# ╠═7813b69c-1952-11eb-1aad-fd97b92acff1
# ╠═b9812dc0-1953-11eb-3526-a708031e641b
# ╟─57887c06-1959-11eb-2607-4d3433ce86bb
# ╠═64352834-1959-11eb-1223-2d53c66cdbb5
# ╠═bd8e318c-1959-11eb-1cca-9190d74cc911
# ╠═4bdb25ee-195f-11eb-2f5e-01915e6c17d4
# ╠═ce3bc53a-1959-11eb-3634-bd86332337a1
# ╠═d7da7ce4-1959-11eb-2862-7ba40fcae2f9
# ╠═10c3e7b0-1960-11eb-2424-5be77481189c
# ╠═26fec6a8-1960-11eb-29d0-d344ecf551c7
# ╠═44c62212-1960-11eb-36b3-112ebe213462
# ╠═70695932-1960-11eb-0120-bd2fd9cc6774
# ╠═76f9e64c-1960-11eb-35f9-6d14721d2d21
# ╠═81e1ba3a-1960-11eb-0142-cfb217696f84
# ╠═8e61a34c-1960-11eb-2bfd-9f49552d84ed
# ╠═9c974360-1960-11eb-18d3-ff6211ee338d
# ╠═ee6961ee-1960-11eb-2159-b15c13b654e6
# ╠═3a6e64c6-196a-11eb-1d1a-c7e19c9e971c
# ╠═293db5aa-196a-11eb-1930-918249f36aae
# ╠═7259e18c-1974-11eb-3345-579a0a799042
# ╠═6c21d460-1973-11eb-13af-c3d2b10b16d8
# ╠═a0b8a888-1960-11eb-377a-51e381f3bd22
# ╠═b5baebda-1968-11eb-1b0a-3d8f113e55b0
# ╠═68650278-1961-11eb-2c0e-ff85a4bdcd0d
# ╠═9ed51b2a-1961-11eb-2565-5540bdc7a968
# ╠═81fa4310-1961-11eb-13a9-89b0e6ebe9bf
# ╠═7e378a2a-1962-11eb-2507-ef1961e5f5a4
# ╠═98b63bbc-1962-11eb-3fb0-ffffb3fb47da
# ╠═ea06a006-1962-11eb-37e7-05e29b0ad0d8
# ╠═feb7abce-1962-11eb-0d4a-db7f4167dee5
# ╠═2ff1c89c-1967-11eb-0e32-d721d7149536
# ╠═270fdada-1968-11eb-3fdf-396e0da9aab2
# ╠═145cb5fc-1968-11eb-2abc-19352aadd45d
# ╠═1936db8e-1968-11eb-0078-af74996040c5
# ╠═fc030822-196b-11eb-15c1-13ff9d45e23e
# ╠═cc4914ee-196d-11eb-3d00-eda117a451d4
# ╠═7305f74e-196d-11eb-2b4e-95c24a81a15f
# ╠═da599c0c-196d-11eb-128c-b96f052f7b4f
# ╟─6bbbdd72-196e-11eb-0446-934abb82f41c
# ╠═1c709af0-196e-11eb-1d51-9106d29ec60c
# ╠═3a044936-196e-11eb-03e1-650c6f80e4ad
# ╠═5f06411c-196e-11eb-1d52-4b3824b4e542
# ╠═915269e8-196e-11eb-0d9c-1b7d57fc3ea8
# ╠═af93d00e-196e-11eb-1cf9-31490dc68c04
# ╟─7e9c446a-1987-11eb-2376-2f158aaeafac
# ╠═87042cbc-1987-11eb-24aa-edca0ff78613
