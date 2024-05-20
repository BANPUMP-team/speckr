# speckr
An enhanced implementation of the SpeckR cipher as described in https://link.springer.com/article/10.1007/s11042-020-09625-8

We managed to produce random output with only 3 rounds, testing with AIS31 tests and STS v3.2.6 from NIST.

Randomness Testing: 
    sts  -i 1024 -I 1 -F r 1gb_of_output.bin
    
