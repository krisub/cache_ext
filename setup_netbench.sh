#!/bin/bash

sudo pkill net_leveldb

echo "removing data directories..."
sudo rm -rf /mydata/db_A /mydata/db_B
mkdir -p /mydata/db_A /mydata/db_B

echo "Launching DB A on Port 9001..."
sudo cgexec -g memory:cache_ext_test ./net_leveldb 9001 /mydata/db_A &

echo "Launching DB B on Port 9002..."
sudo cgexec -g memory:cache_ext_test ./net_leveldb 9002 /mydata/db_B &

echo "Servers running. Ready for traffic."