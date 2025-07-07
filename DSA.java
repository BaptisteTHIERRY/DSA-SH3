package DSA;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class DSA {

    public int L; // = 1024 for the tests
    public int N; // = 160 for the tests
    public BigInteger p; // Prime modulus where 2**(L–1) < p < 2**L
    public BigInteger q; // Prime divisor of (p-1), where 2**(N–1) < q < 2**N
    public BigInteger g; // a generator of the subgroup of order q mod p, such that 1 < g < p
    public BigInteger y; // The public key, where y = g^x mod p.

    private BigInteger x; // The secret key that is a randomly or pseudorandomly generated in the range [1,q-1]
    private BigInteger k; // a secret number that is unique to each message and randomly or pseudorandomly generated, such that 0 < k < q
    private BigInteger k_1; // Inverse of k modulus q
    private BigInteger r; // (g**k mod p) mod q

    public DSA(int N, BigInteger p, BigInteger q, BigInteger g){
        this.N = N;
        this.p = p;
        this.q = q;
        this.g = g;
        this.x = new BigInteger(this.N,new Random()).mod(q);
        while(this.x.equals(BigInteger.ZERO)){this.x = new BigInteger(this.N,new Random()).mod(this.q);} // if x = 0 
        this.y = (this.g).modPow(this.x, this.p);
        this.nonce();
    }

    private void nonce(){
        this.k = new BigInteger(this.N,new Random()).mod(this.q);
        while(this.k.equals(BigInteger.ZERO)){this.k = new BigInteger(this.N,new Random()).mod(this.q);} // if k = 0 
        this.k_1 = (this.k).modInverse(this.q);
        this.r = (this.g).modPow(this.k, this.p).mod(this.q);
        if((this.r).equals(BigInteger.ZERO)){this.nonce();} // if r = 0 then we generate a new value of k
    }
 
    public BigInteger [] signature(String M) throws NoSuchAlgorithmException, UnsupportedEncodingException{

        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        byte[] z_ = md.digest(M.getBytes("UTF-8"));
        BigInteger z = new BigInteger(z_);
        z = z.clearBit(Math.min(this.N, z.bitCount())); // z is the min(N, bitSize(z_)) of hash(M)
        BigInteger s = this.k_1.multiply(z.add(this.x.multiply(this.r))).mod(this.q);
        BigInteger [] sign = {r,s};
        this.nonce();
        if(s.equals(BigInteger.ZERO)){this.signature(M);} // if s = 0 then we generate a new value of k
        return sign;
    }

    public static boolean verification(String M, BigInteger [] sign, BigInteger q, BigInteger p, BigInteger y, BigInteger g, int N) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        if(sign.length != 2) {return false;}
        BigInteger r_ = sign[0];
        BigInteger s_ = sign[1];

        BigInteger w = s_.modInverse(q);

        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        byte[] z_ = md.digest(M.getBytes("UTF-8"));
        BigInteger z = new BigInteger(z_);
        z = z.clearBit(Math.min(N, z.bitCount())); // z is the min(N, bitSize(z_)) of hash(M)

        BigInteger u1 = z.multiply(w).mod(q);
        BigInteger u2 = r_.multiply(w).mod(q);

        BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);

        return v.equals(r_);
    }
}
