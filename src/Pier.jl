module Pier

using Distributed

const FERRYSIZE = "SLOTHROP_PIER_SIZE" in keys(ENV) ? ENV["SLOTHROP_PIER_SIZE"] : 1024
const FERRY = RemoteChannel(() -> Channel(FERRYSIZE))


function embark(x)
    put!(FERRY, x)
end


function disembark()
    @show (myid(), isready(FERRY))
    take!(FERRY)
end

end # End module
