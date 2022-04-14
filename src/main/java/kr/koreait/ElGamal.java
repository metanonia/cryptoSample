package kr.koreait;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ElGamal {

    public static final KeyPair genKeyPair()
    {

        return generateElGamalKeyPair(2048);
    }

    public static final KeyPair generateElGamalKeyPair(int keySize)
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static final String writePrivatePEM(PrivateKey privateKey) throws IOException {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    public static PrivateKey readPrivatePEM(String privatePem) {
        PrivateKey privateKey = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyFactory factory = KeyFactory.getInstance("ELGAMAL", "BC");
            PemReader pemReader = new PemReader(new StringReader(privatePem));

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            privateKey =  factory.generatePrivate(privKeySpec);
            pemReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return privateKey;
    }


    public static final String writePublicPEM(PublicKey publicKey) throws IOException {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        pemWriter.close();

        return writer.toString();
    }

    public static PublicKey readPublicPEM(String publicPem) {
        PublicKey publicKey = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyFactory factory = KeyFactory.getInstance("ELGAMAL", "BC");
            PemReader pemReader = new PemReader(new StringReader(publicPem));

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
            publicKey =  factory.generatePublic(keySpec);
            pemReader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public static String encrypt(PublicKey publicKey, String message) {
        try {
            Cipher c1 = Cipher.getInstance("ElGamal", "BC");
            c1.init(Cipher.ENCRYPT_MODE, publicKey, new SecureRandom());
            return Hex.toHexString(c1.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(PrivateKey privateKey, String message) {
        try {
            byte[] bytes = Hex.decode(message);
            Cipher c1 = Cipher.getInstance("ElGamal", "BC");
            c1.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(c1.doFinal(bytes));
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}