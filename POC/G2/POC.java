import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;

public class POC {

    private static final BigInteger e = new BigInteger(
            "44bb1ff6c2b674798e09075609b7883497ae2e2d7b06" +
            "861ef9850e26d1456280523319021062c8743544877923" +
            "fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c8" +
            "21cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc1" +
            "7e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb6" +
            "23ad507d6b246a1f0c3cc419f155", 16);

    private static final BigInteger n = new BigInteger(
            "94f28651e58a75781cfe69900174b86f855f092f09e3" +
            "da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e" +
            "5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f4" +
            "14918b7d13513ca1110ed80bd2532f8a7aab0314bf54fc" +
            "af621eda74263faf2a5921ffc515097a3c556bf86f2048" +
            "a3c159fccfee6d916d38f7f23f21", 16);

    private byte[] randomIv;

    public POC() { }

    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] RSAEncryption(byte[] message) {
        BigInteger m = new BigInteger(1, message);
        return m.modPow(e, n).toByteArray();
    }

    public byte[] RSAEncryptionPKCS1(byte[] message) {
        PKCS1 pkcs1 = new PKCS1();
        byte[] messageWithPadding = pkcs1.bourragePKCS1(message);
        return RSAEncryption(messageWithPadding);
    }

    public byte[] length128(byte[] bytes) {
        byte[] res = new byte[128];
        if (bytes.length > 128) {
            System.arraycopy(bytes, 1, res, 0, res.length);
        } else if (bytes.length == 128) {
            return bytes;
        } else {
            System.out.println("Attention le bourrage est inférieur à 128 octets");
        }
        return res;
    }

    public byte[] encryptFileWithPKCS5(String source, byte[] key) {
        byte[] fileWithPadding = Aes.pkcs5(source);
        Aes.longueur_de_la_clef = key.length;
        Aes.extended_key = Diversification.calcule_la_clef_etendue(key);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for (int i = 0; i < fileWithPadding.length; i+=16) {
            byte[] bloc = Aes.getBloc(fileWithPadding, i, i + 15);
            bloc = Aes.xor(bloc, this.getRandomIv());                  // XOR avec le vecteur d'initialisation
            bloc = Aes.chiffrer(bloc);
            bos.writeBytes(bloc);
            this.setRandomIv(bloc);                                    // Nouveau vecteur d'initialisation
        }
        return bos.toByteArray();
    }

    public byte[] getRandomIv() {
        return randomIv;
    }

    public void setRandomIv(byte[] randomIv) {
        this.randomIv = randomIv;
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

        POC poc = new POC();
        byte[] secretKey = poc.generateRandomBytes(16);
        byte[] encryptedSecretKey = poc.RSAEncryptionPKCS1(secretKey);
        encryptedSecretKey = poc.length128(encryptedSecretKey);
        Writer.writeBytesToFile(encryptedSecretKey, output, false);
        byte[] randomIv = poc.generateRandomBytes(16);
        poc.setRandomIv(randomIv);
        Writer.writeBytesToFile(randomIv, output, true);
        byte[] encrypedFile = poc.encryptFileWithPKCS5(source, secretKey);
        Writer.writeBytesToFile(encrypedFile, output, true);

    }

}
