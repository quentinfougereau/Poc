import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

public class dPOC {

    public static void main(String[] args) {

        if (args.length < 2) {
            System.out.println("Usage: java dPOC <fichier> <mot de passe>");
            System.exit(1);
        }

        String file = args[0];

        if (!new File(file).canRead()) {
            System.out.println("Le fichier " + file + " n'existe pas");
            System.exit(1);
        }

        String output;
        if (file.contains("-encrypted")) {
            output = file.replace("-encrypted", "-decrypted");
        } else {
            String[] splitFile = file.split("\\.");
            output = splitFile[0] + "-decrypted." + splitFile[1];
        }
        System.out.println("Fichier de sortie : " + output);

        String password = args[1];


        byte[] shasum;

        /* 1. Resumé SHA-1 */
        shasum = getSHA1Hash(password);

        /* 2. Construction de d (BigInteger) correspondant au résumé */
        BigInteger d = new BigInteger(1, shasum);


        /* 3. Construction de n (module publique) */
        BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3" +
                "da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e" +
                "5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f4" +
                "14918b7d13513ca1110ed80bd2532f8a7aab0314bf54fc" +
                "af621eda74263faf2a5921ffc515097a3c556bf86f2048" +
                "a3c159fccfee6d916d38f7f23f21", 16);


        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        /* 4. Construction de la clé privée RSA associée à n et d */
        RSAPrivateKey privateKey = createRSAPrivateKey(n, d);


        /* 5. Extraction et déchiffrement des 128 octets au début du fichier (pour produire la clé AES) */
        Key secretKeySpec = decryptAESkey(fis, privateKey);


        /* 6. Extraction du vecteur d'initialisation (16 octets) */
        byte[] iv = extractIV(fis);


        /* 7. Déchiffrement du fichier avec la clé AES et le vecteur d'initialisation */
        decryptFile(fis, secretKeySpec, iv, output);


    }

    static byte[] getSHA1Hash(String value) {
        MessageDigest hash = null;
        try {
            hash = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        hash.update(value.getBytes());
        return hash.digest();
    }

    static RSAPrivateKey createRSAPrivateKey (BigInteger n, BigInteger d) {
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
        RSAPrivateKey privateKey = null;
        try {
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    static Key decryptAESkey(FileInputStream fis, RSAPrivateKey privateKey) {
        byte[] encryptedAESKey = new byte[128];
        byte[] AESKey = new byte[16];
        try {
            fis.read(encryptedAESKey, 0, encryptedAESKey.length);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            AESKey = cipher.doFinal(encryptedAESKey);
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("Mauvais mot de passe");
            System.exit(1);
        }
        return new SecretKeySpec(AESKey, "AES");
    }

    static byte[] extractIV(FileInputStream fis) {
        byte[] iv = new byte[16];
        try {
            fis.read(iv, 0, iv.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return iv;
    }

    static void decryptFile(FileInputStream fis, Key secretKeySpec, byte[] iv, String output) {
        byte[] buffer = new byte[1024];
        int nbBytesRead;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
            FileOutputStream fos = new FileOutputStream(output);
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            while ( (nbBytesRead = cis.read(buffer)) != -1 ) {
                fos.write(buffer, 0, nbBytesRead);
            }
            fis.close();
            fos.close();
            cis.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IOException e) {
            e.printStackTrace();
        }
    }

}
