
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * FileEncryptor class
 * @author Ghattas Farah
 */
public class FileEncryptor3 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor3.class.getSimpleName());

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
                char[] pw = args2[1];
                String plaintext = new String(args2[2]);
                String cipher = new String(args2[3]);
                enc(pw, plaintext, cipher);
            } else if (Arrays.equals(args2[0], "dec".toCharArray())) {
                char[] pw = args2[1];
                String cipher = new String(args2[2]);
                String plaintext = new String(args2[3]);
                dec(pw, cipher, plaintext);
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
    private static void enc(char[] pw, String plaintext, String ciphertext) {

        try {
            SecureRandom rm = new SecureRandom();
            byte[] salt = new byte[16];
            rm.nextBytes(salt);

            byte[] initVector = new byte[16];
            rm.nextBytes(initVector);

            // Iteration count
            int count = 6969;

            //generating and hashing the secret key from the password
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(pw, salt, count, 256);
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec); //secret key

            //setting up the generation of secret key from the password
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec keySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
            Cipher pbeCipher = Cipher.getInstance(CIPHER);

            pbeCipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

            System.out.println("Secret key=" + Base64.getEncoder().encodeToString(pbeKey.getEncoded()));

            final Path plaintextPath = Paths.get(plaintext);
            final Path encryptedPath = Paths.get(ciphertext);

            try (InputStream fin = Files.newInputStream(plaintextPath);
                 OutputStream fout = Files.newOutputStream(encryptedPath)) {

                //writing the iv into the file in plaintext
                fout.write(salt);
                fout.write(initVector);

                try (CipherOutputStream cipherOut = new CipherOutputStream(fout, pbeCipher)) {
                    final byte[] bytes = new byte[1024];
                    if (fin != null) {
                        for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                            cipherOut.write(bytes, 0, length);
                        }
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
        }catch (InvalidKeySpecException f){
            System.out.println("Program error, not valid KeySpec.");
            System.exit(0);
        }catch(NoSuchPaddingException g){
            System.out.println("Program error, not valid padding.");
            System.exit(0);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Program error, not valid algorithm.");
            System.exit(0);
        }
    }

    /**
     * Decryption method
     * @param pw
     * @param ciphertext
     * @param plaintext
     */
    private static void dec(char[] pw, String ciphertext, String plaintext){

        try {
            byte[] salt = new byte[16]; //the salt
            int count = 6969; //counter for iterations
            byte[] initVector = new byte[16]; //the iv vector

            final Path encryptedPath = Paths.get(ciphertext);//gets the path of encrypted file
            final Path decryptedPath = Paths.get(plaintext); //creates new output file to be decrypted

            try (InputStream encryptedData = Files.newInputStream(encryptedPath)) {

                encryptedData.read(salt); //reading the salt
                encryptedData.read(initVector); //reading the vector

                //setting up the generation of secret key from the password to decrypt
                SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec pbeKeySpec = new PBEKeySpec(pw, salt, count, 256);
                SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec); //this is the key

                //setting up the generation of secret key from the password
                IvParameterSpec iv = new IvParameterSpec(initVector);
                SecretKeySpec keySpec = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
                Cipher pbeCipher = Cipher.getInstance(CIPHER);

                pbeCipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

                try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, pbeCipher);
                     OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
                    final byte[] bytes = new byte[1024];
                    for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                        decryptedOut.write(bytes, 0, length);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(FileEncryptor3.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
                }
            } catch (InvalidKeySpecException e) {
                Logger.getLogger(FileEncryptor3.class.getName()).log(Level.SEVERE, "Not a valid Key spec, unable to decrypt");
            }

            LOG.info("Decryption complete, open " + decryptedPath);
        }catch (IOException e) {
            System.out.println("File IO error, unable to encrypt. " + e.getMessage());
            System.exit(0);
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
     * This method returns the char array value for the string passed in as an argument for the main.
     * @param args
     * @return
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
     * @param wipeString
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