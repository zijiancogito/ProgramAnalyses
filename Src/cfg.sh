#!/bin/bash

ir=$1
func=$2
opt -dot-dom $ir
dot="dom.$2.dot"
python3 cfg.py $dot
