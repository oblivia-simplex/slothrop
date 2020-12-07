#! /usr/bin/env bash

SLOTHROP_PROCS=4

docker build -t slothrop .

docker container run -it \
    --mount type=bind,src=$(pwd),dst=/root/Slothrop \
    -p 1234:1234 \
    slothrop \
    julia \
    --project \
    -p $SLOTHROP_PROCS \
    -q \
    -i initrepl.jl
