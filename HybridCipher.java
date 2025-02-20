import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class HybridCipher {

    // =============================
    // ===== RSA KEY GENERATION ====
    // =============================
    public static KeyPair generateRSAKeyPair() throws Exception {
        // Generate a 2048-bit RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        return keyGen.generateKeyPair();
    }

    // ================================
    // ===== AES KEY GENERATION ======
    // ================================
    public static byte[] generateAESKey() {
        // Generate 256-bit key (32 bytes)
        byte[] aesKey = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(aesKey);
        return aesKey;
    }

    // ========================================
    // ===== RSA ENCRYPT / DECRYPT AES KEY ====
    // ========================================
    public static byte[] rsaEncryptAESKey(byte[] aesKey, PublicKey publicKey) throws Exception {
        // Using RSA with OAEP (SHA-1 + MGF1) padding
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey);
    }

    public static byte[] rsaDecryptAESKey(byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedAESKey);
    }

    // =========================================
    // ===== MANUAL AES CTR ENCRYPT / DECRYPT ==
    // =========================================
    private static final int AES_BLOCK_SIZE = 16; // 128 bits

    // Helper class to hold result of encryption
    public static class EncryptionResult {
        public final byte[] nonce;
        public final byte[] ciphertext;

        public EncryptionResult(byte[] nonce, byte[] ciphertext) {
            this.nonce = nonce;
            this.ciphertext = ciphertext;
        }
    }

    // Manually encrypt with AES in CTR mode
    public static EncryptionResult aesEncryptCTR(byte[] aesKey, String plaintext) throws Exception {
        // Convert plaintext to bytes
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // Generate 8-byte nonce
        byte[] nonce = new byte[8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        // Create AES/ECB/NoPadding cipher for keystream generation
        Cipher cipherECB = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        cipherECB.init(Cipher.ENCRYPT_MODE, keySpec);

        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        // Number of 16-byte blocks
        int nBlocks = (plaintextBytes.length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

        for (int i = 0; i < nBlocks; i++) {
            // Construct counter = 8-byte nonce + 8-byte block counter
            ByteBuffer counterBuf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(i);
            byte[] counterBlock = concat(nonce, counterBuf.array());

            // Encrypt the counter block to produce keystream
            byte[] keystream = cipherECB.doFinal(counterBlock);

            // Get the correct block slice of plaintext
            int start = i * AES_BLOCK_SIZE;
            int end = Math.min(start + AES_BLOCK_SIZE, plaintextBytes.length);
            byte[] block = Arrays.copyOfRange(plaintextBytes, start, end);

            // XOR block with keystream
            byte[] cipherBlock = xorBytes(block, keystream);
            ciphertextStream.write(cipherBlock);
        }

        return new EncryptionResult(nonce, ciphertextStream.toByteArray());
    }

    // Manually decrypt with AES in CTR mode
    public static String aesDecryptCTR(byte[] aesKey, byte[] nonce, byte[] ciphertext) throws Exception {
        // Same logic as encrypt (CTR encryption == decryption)
        Cipher cipherECB = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        cipherECB.init(Cipher.ENCRYPT_MODE, keySpec);

        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();

        int nBlocks = (ciphertext.length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

        for (int i = 0; i < nBlocks; i++) {
            // Construct counter = 8-byte nonce + 8-byte block counter
            ByteBuffer counterBuf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(i);
            byte[] counterBlock = concat(nonce, counterBuf.array());

            // Encrypt the counter block to produce keystream
            byte[] keystream = cipherECB.doFinal(counterBlock);

            // Slice the ciphertext block
            int start = i * AES_BLOCK_SIZE;
            int end = Math.min(start + AES_BLOCK_SIZE, ciphertext.length);
            byte[] block = Arrays.copyOfRange(ciphertext, start, end);

            // XOR block with keystream
            byte[] plainBlock = xorBytes(block, keystream);
            plaintextStream.write(plainBlock);
        }

        return new String(plaintextStream.toByteArray(), StandardCharsets.UTF_8);
    }

    // ================================
    // ===== SIMULATE BIT ERRORS =====
    // ================================
    public static byte[] simulateBitError(byte[] ciphertext, int numErrors) {
        byte[] corrupted = Arrays.copyOf(ciphertext, ciphertext.length);
        Random rand = new Random();
        int totalBits = corrupted.length * 8;

        for (int i = 0; i < numErrors; i++) {
            int randomBitIndex = rand.nextInt(totalBits);
            int byteIndex = randomBitIndex / 8;
            int bitIndex = randomBitIndex % 8;

            // Flip the bit
            corrupted[byteIndex] ^= (1 << bitIndex);
        }
        return corrupted;
    }

    // ================================
    // ======== HELPER METHODS =======
    // ================================
    private static byte[] xorBytes(byte[] data, byte[] keystream) {
        // XOR up to length of data (keystream can be bigger)
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ keystream[i]);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ================================
    // ============= MAIN =============
    // ================================
    public static void main(String[] args) {
        try {
            // 1) Generate RSA Key Pair for Person B
            System.out.println("=== RSA Key Generation for Person B ===");
            KeyPair rsaKeyPair = generateRSAKeyPair();
            PublicKey rsaPublicKey = rsaKeyPair.getPublic();
            PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
            System.out.println("Person B's RSA Public Key (Base64): " +
                    java.util.Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()));
    
            // 2) Person A generates a 256-bit AES key
            System.out.println("\n-Person A generates AES key-");
            byte[] aesKey = generateAESKey();
            System.out.println("AES key (hex): " + bytesToHex(aesKey));
    
            // 3) Encrypt AES key with Person B's RSA public key
            System.out.println("\n-Encrypt AES key with Person B's RSA Public Key-");
            byte[] encryptedAESKey = rsaEncryptAESKey(aesKey, rsaPublicKey);
            System.out.println("Encrypted AES key (hex): " + bytesToHex(encryptedAESKey));
    
            // 4) Decrypt AES key using Person B's RSA private key
            System.out.println("\n-Person B decrypts the AES key using RSA Private Key-");
            byte[] decryptedAESKey = rsaDecryptAESKey(encryptedAESKey, rsaPrivateKey);
            System.out.println("Decrypted AES key (hex): " + bytesToHex(decryptedAESKey));
    
            // Check if keys match
            if (Arrays.equals(aesKey, decryptedAESKey)) {
                System.out.println("AES key match confirmed!");
            } else {
                throw new RuntimeException("AES key mismatch after RSA decryption!");
            }
    
            // 5) Person A encrypts a message using manual AES CTR mode
            Scanner scanner = new Scanner(System.in);
            System.out.print("\nEnter the message to encrypt: ");
            String message = scanner.nextLine();
    
            System.out.println("\n-Person A encrypts the message using AES CTR mode-");
            EncryptionResult result = aesEncryptCTR(aesKey, message);
            byte[] nonce = result.nonce;
            byte[] ciphertext = result.ciphertext;
            System.out.println("Nonce (hex): " + bytesToHex(nonce));
            System.out.println("Ciphertext (hex): " + bytesToHex(ciphertext));
    
            // 5b) Person B now decrypts the message with the AES key (before corruption)
            System.out.println("\n-Person B decrypts the message using the AES key-");
            String decryptedMessage = aesDecryptCTR(decryptedAESKey, nonce, ciphertext);
            System.out.println("Decrypted Message (no errors): " + decryptedMessage);
    
            // 6) Simulate bit error
            System.out.println("\n-Simulate Bit Error in the Ciphertext-");
            System.out.print("Enter number of random bits to flip: ");
            int numErrors = scanner.nextInt();
            byte[] corruptedCiphertext = simulateBitError(ciphertext, numErrors);
            System.out.println("Corrupted Ciphertext (hex): " + bytesToHex(corruptedCiphertext));
    
            // 7) Decrypt corrupted ciphertext
            System.out.println("\n-Decrypting Corrupted Ciphertext-");
            try {
                String decryptedCorruptedMessage = aesDecryptCTR(decryptedAESKey, nonce, corruptedCiphertext);
                System.out.println("Decrypted Message from Corrupted Ciphertext: " + decryptedCorruptedMessage);
            } catch (Exception e) {
                System.err.println("Error during decryption of corrupted ciphertext: " + e.getMessage());
            }
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
