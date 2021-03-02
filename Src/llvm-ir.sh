#!/bin/bash
###
### llvm-ir out llvm ir cfg
###
### Usage:
###   llvm-ir.sh <dir> <file prefix> <opt level>
###
### Options:
###   <dir>   source code dir
###   <file prefix>  Source code filename prefix e.g. test.c -> test
###   <opt level> compiler optimize level 0 1 2 3
###   -h        Show this message.
help() {
    sed -rn 's/^### ?//;T;p' "$0"
}

if [[ $# == 0 ]] || [[ "$1" == "-h" ]]; then
    help
    exit 1
fi
cd $1
mkdir o$3
clang -O$3 -fno-inline-functions $2.c -o o$3/$2.o
clang -O$3 -fno-inline-functions $2.c -emit-llvm -S -o o$3/$2.ll
cd o$3
opt -dot-cfg ../$2.ll > /dev/null
for file in `ls -a`
do
  if [[ $file == *".dot" ]]
  then
    dot -Tpng -o ${file%.dot}.png $file
    echo $file
    python3 /root/proj/ProgramAnalyses/Src/cfg.py $file
  fi
done