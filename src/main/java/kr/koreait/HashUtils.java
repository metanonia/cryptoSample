package kr.koreait;


import java.math.BigInteger;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HashUtils {
    public static String Sha256(BigInteger message) {
        try {
            MessageDigest sh = MessageDigest.getInstance("SHA-256");
            sh.reset();
            sh.update(message.toByteArray());
            byte[] byteData = sh.digest();

            return Base64.encodeBase64String(byteData);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String Sha256(String message) {
        try {
            MessageDigest sh = MessageDigest.getInstance("SHA-256");
            sh.reset();
            sh.update(message.getBytes());
            byte[] byteData = sh.digest();
            return Base64.encodeBase64String(byteData);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static String Hmac(String secret, String data, String algorithm) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKeySpec);
            byte[] hash = mac.doFinal(data.getBytes());

            return Hex.encodeHexString(hash);
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}