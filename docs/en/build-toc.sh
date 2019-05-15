#!/bin/bash

which doctoc
if [ "$?" -ne "0" ]; then
	echo "Please install doctoc."
	exit 2
fi

for file in adfs.md azure-ad.md contributing.md developer.md tech_notes.md troubleshooting.md ../../README.md; do
	doctoc $file && sed -i "" "/Table of Contents.*generated with/d" $file
done
