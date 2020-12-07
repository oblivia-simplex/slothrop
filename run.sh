#! /usr/bin/env bash

docker container run -it \
    --mount type=bind,src=$PWD/,dst=/root/Slothrop \
    -p 1234:1234 \
    slothrop 
