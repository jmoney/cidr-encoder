#!/bin/bash

for profile in $(ls $1/*.pprof); do
    filename=$(basename ${profile%.pprof})
    go tool pprof -top -lines $profile > $1/$filename.txt
done