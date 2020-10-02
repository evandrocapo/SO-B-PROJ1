#!/bin/bash
echo "Stoping module!"
sudo rmmod cryptodev.ko
lsmod