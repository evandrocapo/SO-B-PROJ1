#!/bin/bash
echo "Stoping module!"
sudo rmmod crypto_aelpp.ko
lsmod