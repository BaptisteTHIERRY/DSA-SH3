package DSA;

import java.math.BigInteger;
import java.util.Random;

public class DSA {
    public int L; // = 1024 for the tests
    public int N; // = 160 for the tests
    public BigInteger p; // Prime modulus where 2**(L–1) < p < 2**L
    public BigInteger q; // Prime divisor of (p-1), where 2**(N–1) < q < 2**N
    public BigInteger g; // a generator of the subgroup of order q mod p, such that 1 < g < p
    private BigInteger x; // The secret key that is a randomly or pseudorandomly generated in the range [1,q-1]
    public BigInteger y; // The public key, where y = g^x mod p.
    private BigInteger k; // a secret number that is unique to each message and randomly or pseudorandomly generated, such that 0 < k < q
    private BigInteger k_1;

    DSA(int L, int N, BigInteger p, BigInteger q, BigInteger g){
        this.L = L;
        this.N = N;
        this.p = p;
        this.q = q;
        this.g = g;
        this.x = new BigInteger(this.N,new Random()).mod(q);
        while(this.x.equals(BigInteger.ZERO)){this.x = new BigInteger(this.N,new Random()).mod(this.q);} // if x = 0 
        this.y = this.g.modPow(this.x, this.p);
        this.k = new BigInteger(this.N,new Random()).mod(this.q);
        while(this.k.equals(BigInteger.ZERO)){this.k = new BigInteger(this.N,new Random()).mod(this.q);} // if k = 0 
        this.k_1 = this.k.modInverse(this.g);
    }

    
}
