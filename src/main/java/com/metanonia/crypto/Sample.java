package com.metanonia.crypto;

import cc.redberry.rings.bigint.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Sample {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        String hash = HashUtils.Sha256("Hash Test");
        System.out.println("Hash : " + hash);

        String text = "Hmac Test";
        String secretkey = "secretkey";
        System.out.println("Hmac-MD5: " + HashUtils.Hmac(secretkey, text, "HmacMD5"));
        System.out.println("Hmac-SHA1: " + HashUtils.Hmac(secretkey, text, "HmacSHA1"));
        System.out.println("Hmac-SHA224: " + HashUtils.Hmac(secretkey, text, "HmacSHA224"));
        System.out.println("Hmac-SHA256: " + HashUtils.Hmac(secretkey, text, "HmacSHA256"));
        System.out.println("Hmac-SHA384: " + HashUtils.Hmac(secretkey, text, "HmacSHA384"));
        System.out.println("Hmac-SHA512: " + HashUtils.Hmac(secretkey, text, "HmacSHA512"));

        KeyPair keyPair = Rsa.generateRsaKeyPair();
        String rsaTest = "RSA test";
        String signRsa = Rsa.sign(rsaTest.getBytes(StandardCharsets.UTF_8),keyPair.getPrivate());
        Boolean checkRsa = Rsa.verify(signRsa, rsaTest.getBytes(StandardCharsets.UTF_8), keyPair.getPublic());
        System.out.println("RSA verify = " + checkRsa.toString());
        String enc = Rsa.encrypt(keyPair.getPublic(), rsaTest.getBytes(StandardCharsets.UTF_8));
        String dec = Rsa.decrypt(keyPair.getPrivate(), enc);
        System.out.println("RSA : " + rsaTest + " = " + dec);

        KeyPair elgamalKey = ElGamal.genKeyPair();
        String elGamalTest = "ElGamal Test";
        String enc2 = ElGamal.encrypt(elgamalKey.getPublic(), elGamalTest.getBytes(StandardCharsets.UTF_8));
        String dec2 = ElGamal.decrypt(elgamalKey.getPrivate(), enc2);
        System.out.println("ElGamal : " + elGamalTest + " = " + dec2);

        KeyPair eccKey = ECC.genKeyPair();
        String eccTest = "ECC Test";
        String signEcc = ECC.sign(eccTest.getBytes(StandardCharsets.UTF_8),eccKey.getPrivate());
        Boolean checkEcc = ECC.verify(signEcc, eccTest.getBytes(StandardCharsets.UTF_8), eccKey.getPublic());
        System.out.println("ECC verify = " + checkEcc.toString());
        String enc3 = ECC.encrypt(eccKey.getPublic(), eccTest.getBytes(StandardCharsets.UTF_8));
        String dec3 = ECC.decrypt(eccKey.getPrivate(), enc3);
        System.out.println("ECC : " + eccTest + " = " + dec3);

        List<List<BigInteger>> pksk = Homomorphic.KeyGen(200);
        // public key
        cc.redberry.rings.bigint.BigInteger p = pksk.get(0).get(0);
        cc.redberry.rings.bigint.BigInteger g = pksk.get(0).get(1);
        cc.redberry.rings.bigint.BigInteger h = pksk.get(0).get(2);
        // secret key
        BigInteger p_sk = pksk.get(1).get(0);
        BigInteger x = pksk.get(1).get(1);

        // Encryption/Decryption
        cc.redberry.rings.bigint.BigInteger message = new cc.redberry.rings.bigint.BigInteger("123");
        List<cc.redberry.rings.bigint.BigInteger> encrypt = Homomorphic.Encrypt(p, g, h, message);
        cc.redberry.rings.bigint.BigInteger decrypt = Homomorphic.Decrypt(p_sk, x, encrypt.get(0), encrypt.get(1));
        System.out.println("Homomorphic: "+ message.toString() + " = " + decrypt.toString());
        // Signature/Verify
        cc.redberry.rings.bigint.BigInteger pPrime = p.subtract(cc.redberry.rings.bigint.BigInteger.ONE).divide(cc.redberry.rings.bigint.BigInteger.TWO);
        List<cc.redberry.rings.bigint.BigInteger> sig = Homomorphic.Signature(p, pPrime, g, x, message);
        Boolean check = Homomorphic.Verify(p, g, h, message, sig);
        System.out.println("Homomorphic veryfi: " + check.toString());
        // Homomorphic
        cc.redberry.rings.bigint.BigInteger value1 = new cc.redberry.rings.bigint.BigInteger("7");
        cc.redberry.rings.bigint.BigInteger value2 = new cc.redberry.rings.bigint.BigInteger("8");
        List<cc.redberry.rings.bigint.BigInteger> eValue1 = Homomorphic.Encrypt(p, g, h, value1);
        List<cc.redberry.rings.bigint.BigInteger> eValue2 = Homomorphic.Encrypt(p, g, h, value2);
        List<cc.redberry.rings.bigint.BigInteger> eValue3 = new ArrayList<cc.redberry.rings.bigint.BigInteger>(
                Arrays.asList(eValue1.get(0).multiply(eValue2.get(0)).mod(p), eValue1.get(1).multiply(eValue2.get(1)).mod(p)));
        cc.redberry.rings.bigint.BigInteger dValue = Homomorphic.Decrypt(p_sk, x, eValue3.get(0), eValue3.get(1));
        System.out.println(value1.toString()+"*"+value2.toString()+"="+dValue.toString());
        // different random vaile
        cc.redberry.rings.bigint.BigInteger value4 = new cc.redberry.rings.bigint.BigInteger("11");
        cc.redberry.rings.bigint.BigInteger value5 = new cc.redberry.rings.bigint.BigInteger("3");
        List<cc.redberry.rings.bigint.BigInteger> eValue4 = Homomorphic.Encrypt(p, g, h, value4);
        List<cc.redberry.rings.bigint.BigInteger> eValue5 = Homomorphic.Encrypt(p, g, h, value5);
        List<cc.redberry.rings.bigint.BigInteger> eValue6 = new ArrayList<cc.redberry.rings.bigint.BigInteger>(
                Arrays.asList(eValue4.get(0).multiply(eValue5.get(0)).mod(p), eValue4.get(1).multiply(eValue5.get(1)).mod(p)));
        cc.redberry.rings.bigint.BigInteger dValue2 = Homomorphic.Decrypt(p_sk, x, eValue6.get(0), eValue6.get(1));
        System.out.println(value4.toString()+"*"+value5.toString()+"="+dValue2.toString());
        // same random value
        cc.redberry.rings.bigint.BigInteger value7 = new cc.redberry.rings.bigint.BigInteger("12");
        cc.redberry.rings.bigint.BigInteger value8 = new cc.redberry.rings.bigint.BigInteger("15");
        List<cc.redberry.rings.bigint.BigInteger> eValue7 = Homomorphic.Encrypt(p, g, h, value7);
        List<cc.redberry.rings.bigint.BigInteger> eValue8 = Homomorphic.Encrypt(p, g, h, value8);
        List<cc.redberry.rings.bigint.BigInteger> eValue9 = new ArrayList<cc.redberry.rings.bigint.BigInteger>(
                Arrays.asList(eValue7.get(0).multiply(eValue8.get(0)).mod(p), eValue7.get(1).multiply(eValue8.get(1)).mod(p)));
        cc.redberry.rings.bigint.BigInteger dValue3 = Homomorphic.Decrypt(p_sk, x, eValue9.get(0), eValue9.get(1));
        System.out.println(value7.toString()+"*"+value8.toString()+"="+dValue3.toString());
    }

}
