'''Crypton Native API'''

'''LOG:'''

2014-05-09: First commit, just to get other's eyeballs on it. So far I have experimented with OpenSSL, but discovered that OpenSSL does not handle ElGamal keypairs. I am using libgcrypt instead and frankly, it seems like a much easier to use library and just as portable.

'''Dependencies:'''

clang, llvm, etc...

libgcrypt
libgpg-error

* I am compiling these 2 on linux in /opt/var to keep things isolated from the rest of the linux system.

* On MacOS, once we have this API feature complete, it will make sense to integarte with https://github.com/x2on/libgcrypt-for-ios, which I was easily able to compile on my Mac.

* I have started to integrate this code with the "Check" unit testing on C. More on this later.

* Once you have the dependencies installed, you can compile any of the individual C files like so:

clang crypton_pbkdf2.c -I /var/opt/lib -I /var/opt/include -lgcrypt -lgpg-error -o pbkdf
