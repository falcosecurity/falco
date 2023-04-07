#!/bin/bash
sudo mkdir -p /etc/clouddefense
sudo apt-get update
sudo apt-get install -y make clang llvm
cd driver/bpf && make
echo "Compiling BPF probe"
sudo cp probe.o /etc/clouddefense/probe.o
cd ../../
sudo cp clouddefense.yaml /etc/clouddefense/
sudo cp custom_rules.yaml /etc/clouddefense/
sudo cp clouddefenseai-agent /usr/bin/clouddefenseai-agent
sudo cp -r ./.glibc /usr/bin/.glibc
echo "Successfully installed clouddefenseai-agent"
echo "Open a root shell,set the COLLECTOR_URL environment variable and run clouddefenseai-agent to get started"
