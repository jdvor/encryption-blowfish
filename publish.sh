#!/usr/bin/env bash

[[ -z "$1" ]] && apikey=$NUGET_APIKEY_BLOWFISH || apikey=$1

if [ -z "$apikey" ]; then
    echo "No API key provided." 1>&2
    exit 1
fi

pub=0
shopt -s nullglob
for file in ./publish/*.{nupkg,snupkg} ; do
    dotnet nuget push "$file" -k "$apikey" -s https://api.nuget.org/v3/index.json --skip-duplicate
    pub=$((pub + 1))
done
shopt -u nullglob

if [[ $pub -eq 0 ]]; then
    echo "Nothing has been published." 1>&2
    exit 2
fi
