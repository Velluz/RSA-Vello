package it.vello;

import java.math.BigInteger;
import java.util.Random;
import java.util.StringTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAEncryptor {
    private static final Logger logger = LogManager.getLogger(RSAEncryptor.class);
    private final BigInteger n;
    private final BigInteger e;
    private final BigInteger d;

    public RSAEncryptor() {
        Random rng = new Random();
        BigInteger p = BigInteger.probablePrime(1024, rng);
        BigInteger q = BigInteger.probablePrime(1024, rng);

        logger.info("Generated primes p={} and q={}", p, q);

        this.n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        this.e = findCoPrime(phi);
        this.d = e.modInverse(phi);

        logger.info("Public key (e, n): ({}, {})", e, n);
        logger.info("Private key (d, n): ({}, {})", d, n);
    }

    private BigInteger findCoPrime(BigInteger phi) {
        BigInteger coPrime = new BigInteger("3");
        while (!phi.gcd(coPrime).equals(BigInteger.ONE)) {
            coPrime = coPrime.add(BigInteger.TWO);
        }
        return coPrime;
    }

    public String encrypt(String plaintext) {
        logger.info("Encrypting text: {}", plaintext);
        StringBuilder ciphertext = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            BigInteger m = BigInteger.valueOf((int) c);
            BigInteger encrypted = m.modPow(e, n);
            ciphertext.append(encrypted).append(";");
        }
        logger.info("Ciphertext: {}", ciphertext);
        return ciphertext.toString();
    }

    public String decrypt(String ciphertext) {
        logger.info("Decrypting text: {}", ciphertext);
        StringTokenizer tokenizer = new StringTokenizer(ciphertext, ";");
        StringBuilder plaintext = new StringBuilder();
        while (tokenizer.hasMoreTokens()) {
            BigInteger encrypted = new BigInteger(tokenizer.nextToken());
            BigInteger decrypted = encrypted.modPow(d, n);
            plaintext.append((char) decrypted.intValue());
        }
        logger.info("Decrypted text: {}", plaintext);
        return plaintext.toString();
    }
}
