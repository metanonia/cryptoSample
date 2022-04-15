package com.metanonia.crypto;


import cc.redberry.rings.Ring;
import cc.redberry.rings.bigint.BigInteger;

import java.util.*;

import static cc.redberry.rings.Rings.Z;
import static cc.redberry.rings.Rings.Zp;

public final class Homomorphic {
    /**
     * Security of the ElGamal algorithm depends on the difficulty of computing discrete logs
     * in a large prime modulus
     *
     * - Theorem 1 : a in [Z/Z[p]] then a^(p-1) [p] = 1
     * - Theorem 2 : the order of an element split the order group
     */

    public static BigInteger TWO = new BigInteger("2");

    /**
     * Generate the public key and the secret key for the ElGamal encryption.
     *
     * @param n key size
     */
    public static List<List<BigInteger>> KeyGen(int n) {
        // (a) take a random prime p with getPrime() function. p = 2 * p' + 1 with prime(p') = true
        BigInteger p = getPrime(n, 40, new Random());
        // (b) take a random element in [Z/Z[p]]* (p' order)
        BigInteger g = randNum(p, new Random());
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(TWO);

        while (!g.modPow(pPrime, p).equals(BigInteger.ONE)) {
            if (g.modPow(pPrime.multiply(TWO), p).equals(BigInteger.ONE))
                g = g.modPow(TWO, p);
            else
                g = randNum(p, new Random());
        }

        // (c) take x random in [0, p' - 1]
        BigInteger x = randNum(pPrime.subtract(BigInteger.ONE), new Random());
        BigInteger h = g.modPow(x, p);
        // secret key is (p, x) and public key is (p, g, h)
        List<BigInteger> sk = new ArrayList<>(Arrays.asList(p, x));
        List<BigInteger> pk = new ArrayList<>(Arrays.asList(p, g, h));
        // [0] = pk, [1] = sk
        return new ArrayList<>(Arrays.asList(pk, sk));
    }

    /**
     * Encrypt ElGamal
     *
     * @param (p,g,h) public key
     * @param message message
     */
    public static List<BigInteger> Encrypt(BigInteger p, BigInteger g, BigInteger h, BigInteger message) {
        BigInteger pPrime = p.subtract(BigInteger.ONE).divide(TWO);
        // TODO [0, N -1] or [1, N-1] ?
        BigInteger r = randNum(pPrime, new Random());
        // encrypt couple (g^r, m * h^r)
        return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
    }

    public static List<BigInteger> Encrypt(BigInteger p, BigInteger g, BigInteger h, BigInteger r, BigInteger message) {
        // encrypt couple (g^r, m * h^r)
        return new ArrayList<>(Arrays.asList(g.modPow(r, p), message.multiply(h.modPow(r, p))));
    }

    /**
     * Decrypt ElGamal
     *
     * @param (p,x) secret key
     * @param (gr,mhr) (g^r, m * h^r)
     * @return the decrypted message
     */
    public static BigInteger Decrypt(BigInteger p, BigInteger x, BigInteger gr, BigInteger mhr) {
        BigInteger hr = gr.modPow(x, p);
        return mhr.multiply(hr.modInverse(p)).mod(p);
    }

    public static List<BigInteger> Signature(BigInteger p, BigInteger pPrime, BigInteger g, BigInteger x, BigInteger message) {
        Ring<BigInteger> ring = Zp(Z.valueOf(pPrime));
        BigInteger r;
        BigInteger s;
        do {
            BigInteger k = randNum(pPrime, new Random());
            BigInteger invK = ring.reciprocal(Z.valueOf(k));
            r = g.modPow(k, p);
            s = ((Objects.requireNonNull(HashUtils.SHA256(message)).subtract(x.multiply(r)))
                    .multiply(invK)).mod(pPrime);
        } while (s.compareTo(BigInteger.ZERO) == 0);
        return new ArrayList<>(Arrays.asList(r, s));
    }

    public static Boolean Verify(BigInteger p, BigInteger g, BigInteger y, BigInteger message, List<BigInteger>list) {
        BigInteger r = list.get(0);
        BigInteger s = list.get(1);
        if((r.compareTo(BigInteger.ZERO)>0 && r.compareTo(p)<0) &&
                (s.compareTo(BigInteger.ZERO)>0 && s.compareTo(p.subtract(BigInteger.ONE))<0)) {
            BigInteger tmp1 = g.modPow(Objects.requireNonNull(HashUtils.SHA256(message)), p);
            BigInteger tmp2 = y.modPow(r,p).multiply(r.modPow(s, p)).mod(p);
            return tmp1.compareTo(tmp2) == 0;
        }
        else return false;
    }

    /**
     * Return a prime p = 2 * p' + 1
     *
     * @param nb_bits   is the prime representation
     * @param certainty probability to find a prime integer
     * @param prg       random
     * @return p
     */
    public static BigInteger getPrime(int nb_bits, int certainty, Random prg) {
        BigInteger pPrime = new BigInteger(nb_bits, certainty, prg);
        // p = 2 * pPrime + 1
        BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

        while (!p.isProbablePrime(certainty)) {
            pPrime = new BigInteger(nb_bits, certainty, prg);
            p = pPrime.multiply(TWO).add(BigInteger.ONE);
        }
        return p;
    }

    /**
     * Return a random integer in [0, N - 1]
     */
    public static BigInteger randNum(BigInteger N, Random prg) {
        return new BigInteger(N.bitLength() + 100, prg).mod(N);
    }
}