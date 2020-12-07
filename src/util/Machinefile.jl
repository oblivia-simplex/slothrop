module Machinefile

using Sockets
using Distributed
using TOML

const DEFAULT_PORT = 22


function whoami()
    chomp(read(`whoami`, String))
end


Base.@kwdef struct Host
    procs::Int
    user::String
    host::String
    port::Int
    bindaddr::String
    bindport::Int
end

const MachineSpec = Tuple{String, Int64}

function to_spec(h::Host)::MachineSpec
    str = "$(h.user)@$(h.host):$(h.port) $(h.bindaddr):$(h.bindport)"
    count = h.procs
    return (str, count)
end



function parse_machines(path)
    conf = TOML.parsefile(path)
    @show conf

    function destructure(m)
        println("------------------------")
        @show m
        @show procs = get(m, "procs", 1)
        @show user = get(m, "user", whoami())
        @show host = get(m, "host", "localhost")
        @show port = get(m, "port", DEFAULT_PORT)
        @show bindaddr = get(m, "bindaddr", "0.0.0.0")
        @show bindport = get(m, "bindport", 0)

        @show Host(procs=procs,
             user=user,
             host=host,
             port=port,
             bindaddr=bindaddr,
             bindport=bindport)
    end

    Dict([p.first => destructure(p.second) for p in conf])

end

function launch_workers(path)
    to_spec.(parse_machines(path) |> values) |> addprocs
end


end # end module
