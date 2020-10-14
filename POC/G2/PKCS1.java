import java.util.Random;

public class PKCS1 {

    public byte[] bourragePKCS1(byte[] m) {
        byte[] res = new byte[128];
        res[0] = 0x00;
        res[1] = 0x02;
        for (int i = 2; i < 128 - m.length - 1; i++) {
            res[i] = (byte) getRandomNumberInRange(0x01, 0xFF);

        }
        res[128 - m.length] = 0x00;
        for (int i = 0; i < m.length; i++) {
            res[(128 - m.length) + i] = m[i];
        }
        return res;
    }

    private static int getRandomNumberInRange(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("max must be greater than min");
        }

        Random r = new Random();
        return r.nextInt((max - min) + 1) + min;
    }

}
