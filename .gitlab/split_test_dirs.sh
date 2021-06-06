#!/bin/bash


ARTIFACTS_FOLDER=${ARTIFACTS_FOLDER:-"./artifacts"}
mkdir -p "$ARTIFACTS_FOLDER/test_groups"
fd --glob '*_test.py' ./Packs | grep -E '^Packs/.*?/' --only-matching | uniq -c | sort -nr | grep -E 'Packs/.*$' --only-matching | uniq > "$ARTIFACTS_FOLDER/pack_dirs_list.txt"

group=0
parallel=8
pack_dirs=($(cat "$ARTIFACTS_FOLDER"/pack_dirs_list.txt))
total=${#pack_dirs[@]}
echo "total=$total"
per_parallel_runner=$((total / parallel))
echo "per_parallel_runner=$per_parallel_runner"

for ((i = 0 ; i < total ; i++)); do
    group=$((i % parallel))
    file_name="$ARTIFACTS_FOLDER/test_groups/test_dirs_$group.txt"
    pack=${pack_dirs["$i"]}
    echo "$pack" >> "$file_name"
done
