#! /usr/bin/env bash

[ -n "$PROCS" ] || PROCS=8

exec julia --project -p ${PROCS} ./src/Slothrop.jl
