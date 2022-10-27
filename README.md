my-aes
===
Reference to lkmpg cp16.2 Symmetric key encryption

# AES testing wensite
https://tool.lmeee.com/jiami/aes

# how to use?
## Module part (only)
1. `make`
2. just insmod and execute shell execute.sh
`./execute.sh`
```
ben@ben-OptiPlex-7060:/working/ben/module/my-aes$ ./execute.sh
[191536.433162] [my_aes]: Encrypt:
[191536.433168] [my_aes]: Symmetric key: password123
[191536.433169] [my_aes]: Before encrypt IV: \xd7\xf8@= \xcc\xd5\x03\xb7d\xba\x81ơ\x18 cgroup.threads
[191536.433170] [my_aes]: Before encrypt: Testing
[191536.433171] [my_aes]: Encryption request successful
FMVmemory.lf\xf4\x81;\xc3\xd7\xeb\x11\xa0\x8fn\xcfL\x8d\xff\xff\x01xe2\xc0
[191536.433172] [my_aes]: Decrypt:
[191536.433173] [my_aes]: Symmetric key: password123
[191536.433173] [my_aes]: Before decrypt IV: \xd7\xf8@= \xcc\xd5\x03\xb7d\xba\x81ơ\x18 cgroup.sv\xf4\x81;\xc3\xd7\xe1\xa1cgroup.threads
FMVmemory.lf\xf4\x81;\xc3\xd7\xeb\x11\xa0\x8fn\xcfL\x8d\xff\xff\x01\xe2\xc0
[191536.433175] [my_aes]: Decryption request successful
[191536.433175] [my_aes]: After decrypt: Testing
[191536.440032] [my_aes]: cryptoapi_exit
```
:::info
1. If "Before encrypt" and "After decrypt" is the same, than test is successful
2. If want get same result as encrypt paintext, IV of encrypt and IV of decrypt should be the same
:::
