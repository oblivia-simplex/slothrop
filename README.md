i# slothrop
ROPER III (WIP)

build package
```pkg> build``` 

build docker container
```docker build -t slothrop .```
```./run.sh```
 
repo directory mounted at /root/Slothrop <- $PWD when you launch run.sh

example usage
```julia> using Slothrop
julia> Slothrop.dispatch("config.toml") #Geography struct, dist array```

get population as an ordinary vector of genomes
```julia> population = [Slothrop.Evo.rfetch(g) for g in geo.deme];```

example simple analytics
```julia> using StatsBase
julia> [g.scalar_fitness for g in population] |> skipmissing |> mean
0.14049586776859505```

and you can run Pluto now with
```julia> Pluto.run(host="0.0.0.0", port=1234)```






