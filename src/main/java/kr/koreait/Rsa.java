package kr.koreait;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import sun.security.rsa.RSAKeyPairGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Rsa {
    public static  KeyPair generateRsaKeyPair() {
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator generator= KeyPairGenerator.getInstance("RSA", "BC");

            generator.initialize(1024, secureRandom);

            return generator.generateKeyPair();
        }
        catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Public Key로 RSA 암호화를 수행
     */
    public static String encryptRSA(byte[] plain, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] bytePlain = cipher.doFinal(plain);
            return Base64.getEncoder().encodeToString(bytePlain);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Private Key로 RSA 복호화를 수행
     */
    public static String decryptRSA(String encrypted, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
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

    public static PublicKey getPublicKeyFromBase64Encrypted(String base64PublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedBase64PubKey = Base64.getDecoder().decode(base64PublicKey);

        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decodedBase64PubKey));
    }

    public static PrivateKey getPrivateKeyFromBase64Encrypted(String base64PrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedBase64PrivateKey = Base64.getDecoder().decode(base64PrivateKey);

        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decodedBase64PrivateKey));
    }

    public static RSAPublicKey readPublicPEM(String pem) {
        RSAPublicKey rsaPubKey = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            PemReader pemReader = new PemReader(new StringReader(pem));

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            rsaPubKey = (RSAPublicKey) factory.generatePublic(pubKeySpec);
            pemReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return rsaPubKey;
    }

    public static RSAPrivateKey readPrivatePEM(String pem) {
        RSAPrivateKey privateKey = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            PemReader pemReader = new PemReader(new StringReader(pem));

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            privateKey = (RSAPrivateKey) factory.generatePrivate(privKeySpec);
            String privateKeyModulus = privateKey.getModulus().toString();
            pemReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return privateKey;
    }
}