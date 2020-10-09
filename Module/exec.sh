#!/bin/bash
echo "Executing module!"
make
sudo insmod crypto_aelpp.ko iv="0123456789abcdef" key="0123456789abcdef"
lsmod
