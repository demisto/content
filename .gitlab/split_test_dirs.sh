#!/bin/bash


ARTIFACTS_FOLDER=${ARTIFACTS_FOLDER:-"./artifacts"}
mkdir -p "$ARTIFACTS_FOLDER/test_groups"
find Packs -name '*_test.py' | grep -E '^Packs/.*?/' --only-matching | uniq -c | sort -nr | grep 'Packs/.*' --only-matching | uniq | cut -d'/' -f1,2 > "$ARTIFACTS_FOLDER/pack_dirs_list.txt"

group=0
parallel=8

old_IFS="$IFS"
pack_dirs=()
while IFS='' read -r line; do pack_dirs+=("$line"); done < <(cat "$ARTIFACTS_FOLDER/pack_dirs_list.txt")
IFS="$old_IFS"

total=${#pack_dirs[@]}
echo "total=$total"
per_parallel_runner=$((total / parallel))
echo "per_parallel_runner=$per_parallel_runner"

for ((i = 0 ; i < total ; i++)); do
    group=$((i % parallel))
    group=$((group+=1))
    file_name="$ARTIFACTS_FOLDER/test_groups/test_dirs_$group.txt"
    pack=${pack_dirs["$i"]}
    echo "$pack" >> "$file_name"
done
