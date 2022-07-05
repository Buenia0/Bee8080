#!/bin/bash

if [[ ! -f "Bee8080/libbee8080.a" ]]; then
	echo "Run this script from the directory where you built the Bee8080 engine."
	exit 1
fi

mkdir -p dist/


if [[ -f "bee8080-tests.exe" ]]; then
	for lib in $(ldd bee8080-tests.exe | grep mingw | sed "s/.*=> //" | sed "s/(.*)//"); do
		cp "${lib}" dist
	done
	cp bee8080-tests.exe dist
	cp -r ../tests dist
fi