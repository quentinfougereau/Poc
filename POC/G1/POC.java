import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class POC {

    private static final int IV_LENGTH = 16;
    private static final BigInteger e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06" +
                                                           "861ef9850e26d1456280523319021062c8743544877923" +
                                                           "fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c8" +
                                                           "21cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc1" +
                                                           "7e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb6" +
                                                           "23ad507d6b246a1f0c3cc419f155", 16);

    private static final BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3" +
                                                            "da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e" +
                                                            "5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f4" +
                                                            "14918b7d13513ca1110ed80bd2532f8a7aab0314bf54fc" +
                                                            "af621eda74263faf2a5921ffc515097a3c556bf86f2048" +
                                                            "a3c159fccfee6d916d38f7f23f21", 16);

    private byte[] randomIv;
    private String outputFile;

    public POC(String outputFile) {
        this.outputFile = outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void encryptFile(String transformation, Key key, String fileName, boolean hasRandomness, boolean append) {
        Cipher cipher = null;
        byte[] buffer = new byte[1024];
        int nbBytesRead;
        try {
            cipher = Cipher.getInstance(transformation);
            if (!hasRandomness) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(this.getRandomIv()));
            }
            FileInputStream fis = new FileInputStream(fileName);
            FileOutputStream fos = new FileOutputStream(outputFile, append);
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            while ( (nbBytesRead = cis.read(buffer)) != -1 ) {
                fos.write(buffer, 0, nbBytesRead);
            }
            fis.close();
            fos.close();
            cis.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] encryptBytes(String transformation, Key key, byte[] bytes, boolean hasRandomness) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(transformation);
            if (!hasRandomness) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                this.setRandomIv(generateRandomBytes(IV_LENGTH));
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(this.getRandomIv()));
            }
            return cipher.doFinal(bytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] getRandomIv() {
        return randomIv;
    }

    public void setRandomIv(byte[] randomIv) {
        this.randomIv = randomIv;
    }

    public SecretKey createRandomSecretKey(String algorithm) {
        byte[] key = generateRandomBytes(16);
        return new SecretKeySpec(key, algorithm);
    }

    public RSAPublicKey createRSAPublicKey() {
        RSAPublicKey publicKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
            publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
            exception.printStackTrace();
        }
        return publicKey;
    }

    public static void main(String[] args) {

        if (args.length == 0) {
            System.out.println("Usage: java POC <fichier>");
            System.exit(1);
        }

        String source = args[0];

        if (!new File(source).canRead()) {
            System.out.println("Le fichier " + source + " n'existe pas");
            System.exit(1);
        }

        String[] splitSource = source.split("\\.");
        String output = splitSource[0] + "-encrypted." + splitSource[1];
        System.out.println("Fichier de sortie : " + output);

        POC poc = new POC(output);
        byte[] secretKey = poc.generateRandomBytes(16);
        Key secretKeySpec = new SecretKeySpec(secretKey, "AES");
        RSAPublicKey publicKey = poc.createRSAPublicKey();
        byte[] encryptedSecretKey = poc.encryptBytes("RSA/ECB/PKCS1Padding", publicKey, secretKey, false);
        Writer.writeBytesToFile(encryptedSecretKey, output, false);
        byte[] randomIv = poc.generateRandomBytes(16);
        poc.setRandomIv(randomIv);
        Writer.writeBytesToFile(randomIv, output, true);
        poc.encryptFile("AES/CBC/PKCS5Padding", secretKeySpec, source, true, true);


    }

}
