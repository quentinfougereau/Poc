import java.io.FileOutputStream;
import java.io.IOException;

public class Writer {

    public static void writeBytesToFile(byte[] bytes, String output, boolean append) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(output, append);
            fos.write(bytes, 0, bytes.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void printBytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02X ", b);
        }
        System.out.printf("(%d octets)", bytes.length);
        System.out.println();
    }

    public static void printBytes(byte[] bytes, int length) {
        for (int i = 0; i < length; i++) {
            System.out.printf("%02X ", bytes[i]);
        }
        System.out.println();
    }

}
