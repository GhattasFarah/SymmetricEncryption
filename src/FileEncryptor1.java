import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * FileEncryptor class
 * @author Ghattas Farah
 */
public class FileEncryptor1 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor1.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) {

        try {
            //converting to char array then wiping the strings
            char[][] args2 = toCharArray(args);
            for (String arg : args) {
                stringWiper(arg);
            }
            args = null; //setting the args to null

            if (Arrays.equals(args2[0], "enc".toCharArray())) {
                String plaintext = new String(args2[1]);
                String cipher = new String(args2[2]);
                enc(plaintext, cipher);
            } else if (Arrays.equals(args2[0], "dec".toCharArray())) {
                char[] skey = args2[1];
                char[] iv = args2[2];
                String cipher = new String(args2[3]);
                String plaintext = new String(args2[4]);
                dec(skey, iv, cipher, plaintext);
            } else {
                LOG.log(Level.INFO, "Please enter a valid operation");
                System.exit(0); //exits the program
            }
        }catch (NumberFormatException e) {
            System.out.println("Please enter a valid number." + e.getMessage());
            System.exit(0);
        }
    }

    /**
     * Encryption method
     * @param plaintext
     * @param ciphertext
     */
    private static void enc(String plaintext, String ciphertext) {
        try {
            SecureRandom sr = new SecureRandom();
            byte[] key = new byte[16];
            sr.nextBytes(key); // 128 bit key
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector); // 16 bytes IV
            System.out.println("Random key=" + Base64.getEncoder().encodeToString(key));
            System.out.println("initVector=" + Base64.getEncoder().encodeToString(initVector));
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            final Path plaintextPath = Paths.get(plaintext);
            final Path encryptedPath = Paths.get(ciphertext);

            try (InputStream fin = Files.newInputStream(plaintextPath);
                 OutputStream fout = Files.newOutputStream(encryptedPath);
                 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
                 }) {
                final byte[] bytes = new byte[1024];
                if (fin != null) {
                    for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                        cipherOut.write(bytes, 0, length);
                    }
                }
            } catch (IOException e) {
                LOG.log(Level.INFO, "Unable to encrypt", e);
            }
            LOG.info("Encryption finished, saved at " + encryptedPath);
        }catch (InvalidAlgorithmParameterException a) {
            System.out.println("Program error, not a valid algorithm parameter." + a);
            System.exit(0);
        }catch (InvalidKeyException e) {
            System.out.println("Invalid key was entered, please enter a valid key.");
            System.exit(0);
        } catch(NoSuchPaddingException g){
            System.out.println("Program error, not valid padding.");
            System.exit(0);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Program error, not valid algorithm.");
            System.exit(0);
        }
    }

    /**
     * Decryption method
     * @param k
     * @param vector
     * @param ciphertext
     * @param plaintext
     */
    private static void dec(char[] k, char[] vector, String ciphertext, String plaintext){

        try {
            byte[] key = Base64.getDecoder().decode(new String(k));
            byte[] initVector = Base64.getDecoder().decode(new String(vector));
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            final Path encryptedPath = Paths.get(ciphertext);//gets the path of encrypted file

            final Path decryptedPath = Paths.get(plaintext); //creates new output file to be decrypted

            try (InputStream encryptedData = Files.newInputStream(encryptedPath);
                 CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
                 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor1.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

            LOG.info("Decryption complete, open " + decryptedPath);
        } catch (InvalidAlgorithmParameterException a) {
            System.out.println("Program error, not a valid algorithm parameter." + a);
            System.exit(0);
        }catch (InvalidKeyException e) {
            System.out.println("Invalid key was entered, please enter a valid key.");
            System.exit(0);
        } catch(NoSuchPaddingException g){
            System.out.println("Program error, not valid padding.");
            System.exit(0);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Program error, not valid algorithm.");
            System.exit(0);
        }
    }

    /**
     * This method returns the char array value for the string passed in as an argument.
     * @param args
     * @return char[][]
     */
    private static char[][] toCharArray(String[] args){
        char[][] outputArray = new char[args.length][];
        for(int i = 0; i < args.length; i ++){
            outputArray[i] = args[i].toCharArray();
        }
        return outputArray;
    }

    /**
     * This method wipes a string in order to improve security
     * Got the method from: https://konstantinpavlov.net/blog/2015/08/01/secure-java-coding-best-practices/
     */
    private static void stringWiper(String wipeString){
        try {
            final Field stringValue = String.class.getDeclaredField("value");
            stringValue.setAccessible(true);
            final Object val = stringValue.get(wipeString);
            if(val instanceof byte[]) {
                Arrays.fill((byte[]) val, (byte)0); // in case of compact string in Java 9+
            } else {
                Arrays.fill((char[]) val, '\u0000');
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new Error("Can't wipe string data");
        }
    }
}
