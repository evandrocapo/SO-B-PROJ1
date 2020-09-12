#!/bin/bash
echo "Stoping module!"
sudo rmmod crypto.ko
lsmod