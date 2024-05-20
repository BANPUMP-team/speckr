# speckr
An enhanced implementation of the SpeckR cipher described by the authors of the seminal paper: https://link.springer.com/article/10.1007/s11042-020-09625-8

We managed to produce random output with only 3 rounds, testing with AIS31 tests and STS v3.2.6 from NIST; if resources are very limited, using #define SPECKR_ROUNDS 3 in speckr.h file 187 out of 188 STS tests are passed. AIS31 tests are passed with flying colors.

Using #define SPECKR_ROUNDS 5 passes all randomness tests to the point of plausible deniability. The default SPECKR_ROUNDS value is 7 based on the seminal paper.

    
