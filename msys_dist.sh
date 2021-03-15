#!/bin/bash

if [[ ! -f "libbee8080.a" ]]; then
	echo "Run this script from the directory where you built Bee8080."
	exit 1
fi


if [[ ! -f "bee8080-tests.exe ]]; then
	cp -r ../tests .
fi