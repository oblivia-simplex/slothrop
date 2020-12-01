### A Pluto.jl notebook ###
# v0.12.4

using Markdown
using InteractiveUtils

# ╔═╡ 9e6dd012-1af0-11eb-192e-17f69face72f
using TOML

# ╔═╡ aace9cc6-1af8-11eb-04e7-bd9d2460ac6d
using DataFrames

# ╔═╡ acedb0aa-1af8-11eb-2132-a321f32999a3
using Plots

# ╔═╡ 45c3445c-1af9-11eb-270b-cdebe96a28ac
using StatsBase

# ╔═╡ 729e4e24-1af0-11eb-0d4d-f1a6987e48d5
md"# Trying out the Evo.tournament! function"

# ╔═╡ c7bfb3e0-1af0-11eb-24a4-c905049cc576
PROJECT_DIR = "/home/lucca/src/slothrop"

# ╔═╡ b018b3d6-1af0-11eb-0b87-873ec989c527
include("$(PROJECT_DIR)/src/Evo.jl")

# ╔═╡ 65379bae-1af8-11eb-14b3-27b99c6fd922
cd(PROJECT_DIR)

# ╔═╡ a934c424-1af0-11eb-0eec-d7b39e64752a
config = TOML.parsefile("config.toml")

# ╔═╡ 87e9d75c-1af8-11eb-2771-375b148a8663
geo = Evo.geography(config)

# ╔═╡ a01a0068-1af8-11eb-32de-fbd1653ada8f
fit_series = []

# ╔═╡ 4a95eb4c-1af9-11eb-3d1c-b5976155d80f


# ╔═╡ 18368b3e-1af9-11eb-2265-41bce67ac5eb
for i in 1:10000
	Evo.tournament!(geo)
	mean_fitness = mean(skipmissing([x.scalar_fitness for x in geo.deme]))
	push!(fit_series, mean_fitness)
end

# ╔═╡ e1b6030e-1af9-11eb-1031-a7432538b1eb


# ╔═╡ 3fd9bbca-1af9-11eb-00af-65bed1858409
plot(fit_series)

# ╔═╡ 1fa1e18a-1b0c-11eb-1897-ed26e5e4d9f7
scatter([x.generation for x in geo.deme])

# ╔═╡ 36d98a38-1b0c-11eb-3e85-f5fc45abd483
scatter([length(p.insts) for p in skipmissing([x.phenome for x in geo.deme])])

# ╔═╡ 72b95de4-1b0c-11eb-30ac-4f1472babeeb
scatter([p.ret_count for p in skipmissing([x.phenome for x in geo.deme])])

# ╔═╡ 7a960378-1b0c-11eb-3383-b354446358ec
scatter([length(x.chromosome) for x in geo.deme], color="blue")

# ╔═╡ a02c50e2-1b0c-11eb-350c-19278b485387


# ╔═╡ Cell order:
# ╠═729e4e24-1af0-11eb-0d4d-f1a6987e48d5
# ╠═9e6dd012-1af0-11eb-192e-17f69face72f
# ╠═c7bfb3e0-1af0-11eb-24a4-c905049cc576
# ╠═65379bae-1af8-11eb-14b3-27b99c6fd922
# ╠═a934c424-1af0-11eb-0eec-d7b39e64752a
# ╠═b018b3d6-1af0-11eb-0b87-873ec989c527
# ╠═aace9cc6-1af8-11eb-04e7-bd9d2460ac6d
# ╠═acedb0aa-1af8-11eb-2132-a321f32999a3
# ╠═87e9d75c-1af8-11eb-2771-375b148a8663
# ╠═a01a0068-1af8-11eb-32de-fbd1653ada8f
# ╠═45c3445c-1af9-11eb-270b-cdebe96a28ac
# ╠═4a95eb4c-1af9-11eb-3d1c-b5976155d80f
# ╠═18368b3e-1af9-11eb-2265-41bce67ac5eb
# ╠═e1b6030e-1af9-11eb-1031-a7432538b1eb
# ╠═3fd9bbca-1af9-11eb-00af-65bed1858409
# ╠═1fa1e18a-1b0c-11eb-1897-ed26e5e4d9f7
# ╠═36d98a38-1b0c-11eb-3e85-f5fc45abd483
# ╠═72b95de4-1b0c-11eb-30ac-4f1472babeeb
# ╠═7a960378-1b0c-11eb-3383-b354446358ec
# ╠═a02c50e2-1b0c-11eb-350c-19278b485387
