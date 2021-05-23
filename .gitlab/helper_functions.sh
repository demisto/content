#!/bin/bash

CYAN="\e[0;36m"
CLEAR="\e[0m"
SECTION_START="\e[0Ksection_start:the_time:section_id\r\e[0K${CYAN}section_header${CLEAR}"
SECTION_END="\e[0Ksection_end:the_time:section_id\r\e[0K"

section_start() {
    local section_header section_id start
    start="$SECTION_START"
    if [[ "$#" -eq 1 ]]; then
        section_header="$1"
        section_id="$(echo "$1" | tr -c '[:alnum:]\n\r' '_')"
    elif [[ "$#" -eq 2 ]]; then
        if [[ "$2" =~ -{0,2}collapsed ]]; then
            start="${start/section_id/section_id[collapsed=true]}"
            section_header="$1"
            section_id="$(echo "$1" | tr -c '[:alnum:]\n\r' '_')"
        else
            section_header="$2"
            section_id="$1"
        fi
    elif [[ "$#" -eq 3 && "$3" =~ /^-{0,2}collapsed$/ ]]; then
        start="${start/section_id/section_id[collapsed=true]}"
        section_header="$2"
        section_id="$1"
    else
        echo "section_start should be called with 1-3 args but it was called with $#"
        echo "acceptable usages:"
        echo "    1. section_start \"<section-start-id>\" \"<section-header>\""
        echo "    2. section_start \"<section-header>\""
        echo "    3. section_start \"<section-start-id>\" \"<section-header>\" --collapse"
        echo "    4. section_start \"<section-header>\" --collapse"
        echo "where <section-start-id> is only alphanumeric characters and underscore and"
        echo "--collapse indicates that you would like those log steps to be collapsed in the job log output by default"
        exit 9
    fi
    start_time=$(date +%s)
    start="$(echo "$start" | sed -e "s/the_time/$start_time/" -e "s/section_id/$section_id/" -e "s/section_header/$section_header/")"
    echo -e "$start"
}

section_end() {
    local section_id end
    end="$SECTION_END"
    if [[ "$#" -eq 1 ]]; then
        section_id="$(echo "$1" | tr -c '[:alnum:]\n\r' '_')"
    else
        echo "section_end should be called with 1 arg but it was called with $#"
        echo "acceptable usage:"
        echo "    1. section_end \"<section-start-id>\""
        echo "    2. section_start \"<section-header>\""
        echo "where <section-start-id> or <section-header> is that of the section this marks the end of"
        exit 9
    fi
    end_time=$(date +%s)
    end="$(echo "$end" | sed -e "s/the_time/$end_time/" -e "s/section_id/$section_id/")"
    echo -e "$end"
}
