#!/usr/bin/env bash

# Do NOT change this file!


set -e

cp .pre-push .git/hooks/pre-push
sudo apt-get update -qq
sudo apt-get install -qq -- \
    build-essential \
    curl \
    gcc \
    gcc-multilib \
    openssl \
    python \
    python3 \
    python3-pip \
;

pip3 install -U --user \
    nose \
    requests \
;
