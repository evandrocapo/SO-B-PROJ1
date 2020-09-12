# SO-B-PROJ1

## Summary

1 - Prerequisites

2 - Examples

3 - Module

4 - Program

### Prerequisites

```
sudo apt-get update
sudo apt-get install libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
sudo apt-get install linux-headers-$(uname -r)
sudo apt-get install linux-source
```

### Examples

Code examples

### Module

The operating order is:

1 - File is open (Module lock mutex)

2 - File is readen (Module get the string)

3 - The module read the first string (C) Crypto, (D) Decrypt or (H) Hash

4 - The module read the third hexadecimal string onwards

5 - The module return the result (Module writes to file "/dev/crypto")


### Program

The operating order is:

1 - The program reads the hexadecimal string

2 - The program writes to file "/dev/crypto"

3 - The program read the result from module


### References

`
http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device
https://www.kernel.org/doc/html/v4.12/crypto/index.html
http://www.logix.cz/michal/devel/cryptodev/cryptoapi-demo.c.xp
`