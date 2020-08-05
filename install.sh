#!/bin/bash

sudo pip3 install -r python_requirements.txt
git submodule update --init --recursive
cd recog
bundle install
