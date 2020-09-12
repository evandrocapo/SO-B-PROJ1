#!/bin/bash
echo "Executing module!"
make
sudo insmod crypto.ko
lsmod