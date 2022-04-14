package kr.koreait;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

public class Sample {
    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
        String enc = Rsa.encryptRSA(rsaTest.getBytes(StandardCharsets.UTF_8), keyPair.getPublic());
        String dec = Rsa.decryptRSA(enc, keyPair.getPrivate());
        System.out.println("RSA : " + rsaTest + " = " + dec);

        KeyPair elgamalKey = ElGamal.genKeyPair();
        String elGamalTest = "ElGamal Test";
        String enc2 = ElGamal.encrypt(elgamalKey.getPublic(), elGamalTest);
        String dec2 = ElGamal.decrypt(elgamalKey.getPrivate(), enc2);
        System.out.println("ElGamal : " + elGamalTest + " = " + dec2);

        KeyPair eccKey = ECC.genKeyPair();
        String eccTest = "ECC Test";
        String sign = ECC.sign(eccTest.getBytes(StandardCharsets.UTF_8),eccKey.getPrivate());
        Boolean check = ECC.verify(sign, eccTest.getBytes(StandardCharsets.UTF_8), eccKey.getPublic());
        System.out.println("ECC verify = " + check.toString());
        String enc3 = ECC.encrypt(eccKey.getPublic(), eccTest.getBytes(StandardCharsets.UTF_8));
        String dec3 = ECC.decrypt(eccKey.getPrivate(), enc3);
        System.out.println("ECC : " + eccTest + " = " + dec3);
    }

}
