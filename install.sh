#!/bin/bash

sudo python3 -m pip install -r python_requirements.txt
git submodule update --init --recursive
cd recog
sudo gem install bundler
bundle install
