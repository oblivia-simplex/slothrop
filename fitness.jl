g -> begin
    g.fitness[:ret_count] = g.phenome.ret_count
    # weighting
    g.scalar_fitness = sum(g.fitness.ret_count)
end
