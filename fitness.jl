function fitness_function(phenome)
    [:ret_count => phenome.ret_count]
end

function fitness_weighting(df)::Float64
    sum(df.ret_count)
end
