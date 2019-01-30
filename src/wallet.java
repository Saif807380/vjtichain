import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.nio.charset.*;
import java.security.spec.*;
import java.util.*;

public class wallet {

    private static String getKey(String filename) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }

    public static PrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }
    
    public static PrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("\n", "");
        System.out.println(privateKeyPEM);
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privKey = (PrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }

    public static PublicKey getPrivateKeyFromString2(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("\n", "");
        System.out.println(privateKeyPEM);
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PublicKey pubKey = (PublicKey) kf.generatePublic(keySpec);
        return pubKey;
    }

    public static PublicKey getPublicKey(String filename) throws IOException, GeneralSecurityException {
        String publicKeyPEM = getKey(filename);
        return getPublicKeyFromString(publicKeyPEM);
    }
    
    public static PublicKey getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("\n", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey pubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
        return pubKey;
    }

    public static BigInteger extractR(byte[] signature) throws Exception {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
    }
    
    public static BigInteger extractS(byte[] signature) throws Exception {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        int startS = startR + 2 + lengthR;
        int lengthS = signature[startS + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
    }

    public static byte[] derSign(BigInteger r, BigInteger s) throws Exception {
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        int off = (2 + 2) + rb.length;
        int tot = off + (2 - 2) + sb.length;
        byte[] der = new byte[tot + 2];
        der[0] = 0x30;
        der[1] = (byte) (tot & 0xff);
        der[2 + 0] = 0x02;
        der[2 + 1] = (byte) (rb.length & 0xff);
        System.arraycopy(rb, 0, der, 2 + 2, rb.length);
        der[off + 0] = 0x02;
        der[off + 1] = (byte) (sb.length & 0xff);
        System.arraycopy(sb, 0, der, off + 2, sb.length);
        return der;
    }

    public static void main(String[] args) throws Exception {
        /*
         * Generate an ECDSA signature
         */

        /*
         * Generate a key pair
         */

        // KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        // keyGen.initialize(256, random);

        // KeyPair pair = keyGen.generateKeyPair();
        // PrivateKey priv = pair.getPrivate();
        // PublicKey pub = pair.getPublic();
        PrivateKey p = getPrivateKey("wallet/test");
        // PublicKey p2 = getPrivateKeyFromString2(getKey("wallet/test"));
        /*
         * Create a Signature object and initialize it with the private key
         */

        Signature dsa = Signature.getInstance("SHA256withECDSA");
        dsa.initSign(p);

        String str = "VJTI";
        byte[] strByte = str.getBytes("UTF-8");
        dsa.update(strByte);

        /*
         * Now that all the data to be signed has been read in, generate a
         * signature for it
         */

        byte[] realSig = dsa.sign();
        System.out.println(realSig.length);
        System.out.println("Signature: " + new BigInteger(1, realSig).toString(16));
        System.out.println(dsa.toString());
        System.out.println(realSig.length);

        BigInteger r = extractR(realSig);
        BigInteger s = extractS(realSig);

        System.out.println(r);
        System.out.println(s);

        // //Python
        // Signature DSA = Signature.getInstance("SHA256withECDSA");
        // DSA.initVerify(p2);

        // String str2 = "VJTI";
        // byte[] strByte2 = str2.getBytes("UTF-8");
        // dsa.update(strByte2);
        // System.out.println(DSA.verify(derSign(r, s)));
    }
}