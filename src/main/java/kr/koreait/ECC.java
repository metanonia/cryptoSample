package kr.koreait;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;


public class ECC {
    public static KeyPair genKeyPair() {
        try {
            ECGenParameterSpec pairParams = new ECGenParameterSpec("secp256k1");
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
            gen.initialize(pairParams);
            return gen.generateKeyPair();
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PrivateKey genPrivateKey(BigInteger D) {
        try {
            ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            ECPrivateKeySpec privateKeySpec =new ECPrivateKeySpec(D, parameterSpec);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePrivate(privateKeySpec);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey genPublicKey(PrivateKey privateKey) {
        try {
            ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            BigInteger D = ((ECPrivateKey)privateKey).getD();
            ECPoint PK = parameterSpec.getG().multiply(D);
            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(PK, parameterSpec);
            return KeyFactory.getInstance("EC", "BC").generatePublic(publicKeySpec);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String sign(byte[]msg, PrivateKey privateKey) {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(privateKey);
            ecdsa.update(msg);
            return Hex.encodeHexString(ecdsa.sign());
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Boolean verify(String signed, byte[]msg, PublicKey publicKey) {
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(publicKey);
            ecdsa.update(msg);
            return ecdsa.verify(Hex.decodeHex(signed));
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encrypt(PublicKey publicKey, byte[] plain) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] bytePlain = cipher.doFinal(plain);
            return Base64.getEncoder().encodeToString(bytePlain);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(PrivateKey privateKey, String encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES", "BC");
            byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] bytePlain = cipher.doFinal(byteEncrypted);
            return new String(bytePlain, "utf-8");
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
