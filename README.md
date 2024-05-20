# speckr
An enhanced implementation of the SpeckR cipher as described in https://link.springer.com/article/10.1007/s11042-020-09625-8

We managed to produce random output with only 3 rounds, testing with AIS31 tests and STS v3.2.6 from NIST; if resources are very limited use #define SPECKR_ROUNDS 3 in speckr.h file. 187 out of 188 STS tests are passed. AIS31 passes with flying colors.

The default #define SPECKR_ROUNDS 7 passes all tests to the point of plausible deniability.

    
