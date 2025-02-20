import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;

public class ProductCipher {

    // ----- Utility Functions -----

    // Calculate GCD (greatest common divisor).
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // ----- Affine Cipher -----

    /**
     * Encrypts the text using the Affine Cipher.
     * Converts text to lowercase.
     */
    public static String affineEncrypt(String text, int a, int b) {
        if (gcd(a, 26) != 1) {
            throw new IllegalArgumentException("Key 'a' must be coprime with 26.");
        }

        StringBuilder encrypted = new StringBuilder();
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                // Convert to [0..25]
                int x = Character.toLowerCase(ch) - 'a';
                // Affine encryption: (a*x + b) mod 26
                int encryptedCharVal = (a * x + b) % 26;
                // Convert back to character
                encrypted.append((char) (encryptedCharVal + 'a'));
            } else {
                encrypted.append(ch);
            }
        }
        return encrypted.toString();
    }

    /**
     * Decrypts the text using the Affine Cipher.
     */
    public static String affineDecrypt(String cipher, int a, int b) {
        // Compute modular inverse of 'a' modulo 26 using BigInteger
        BigInteger aBI = BigInteger.valueOf(a);
        BigInteger mod = BigInteger.valueOf(26);
        BigInteger invBI = aBI.modInverse(mod);
        int aInv = invBI.intValue();  // This is the multiplicative inverse of a mod 26

        StringBuilder decrypted = new StringBuilder();
        for (char ch : cipher.toCharArray()) {
            if (Character.isLetter(ch)) {
                // Convert to [0..25]
                int y = Character.toLowerCase(ch) - 'a';
                // Affine decryption: a_inv * (y - b) mod 26
                int decryptedCharVal = (aInv * (y - b)) % 26;
                // Handle negative results from (y - b)
                if (decryptedCharVal < 0) {
                    decryptedCharVal += 26;
                }
                decrypted.append((char) (decryptedCharVal + 'a'));
            } else {
                decrypted.append(ch);
            }
        }
        return decrypted.toString();
    }

    // ----- Columnar Transposition Cipher -----

    /**
     * Validates that the key is a permutation of numbers from 1 to key.length.
     */
    public static void validateTranspositionKey(int[] key) {
        int[] sortedKey = key.clone();
        Arrays.sort(sortedKey);
        // We expect [1, 2, 3, ..., n]
        for (int i = 0; i < key.length; i++) {
            if (sortedKey[i] != (i + 1)) {
                throw new IllegalArgumentException("Transposition key must be a permutation of 1..n (n = key length).");
            }
        }
    }

    /**
     * Encrypts the text using a Columnar Transposition Cipher.
     */
    public static String transpositionEncrypt(String text, int[] key) {
        validateTranspositionKey(key);

        int numCols = key.length;
        // Ceiling division for rows
        int numRows = (text.length() + numCols - 1) / numCols;

        // Fill the matrix row-by-row with string segments
        String[][] matrix = new String[numRows][numCols];
        int index = 0;
        for (int row = 0; row < numRows; row++) {
            for (int col = 0; col < numCols; col++) {
                if (index < text.length()) {
                    matrix[row][col] = String.valueOf(text.charAt(index));
                } else {
                    matrix[row][col] = "";  // Empty
                }
                index++;
            }
        }

        // Sort columns by the key order (we need the column indices in ascending key order)
        // We'll build an array of (keyValue, originalIndex) pairs, then sort by keyValue
        Integer[] colOrder = new Integer[numCols];
        for (int i = 0; i < numCols; i++) {
            colOrder[i] = i; // store original index
        }
        Arrays.sort(colOrder, (i, j) -> Integer.compare(key[i], key[j]));

        // Read the columns in the sorted order
        StringBuilder cipher = new StringBuilder();
        for (int colIndex : colOrder) {
            for (int row = 0; row < numRows; row++) {
                if (!matrix[row][colIndex].isEmpty()) {
                    cipher.append(matrix[row][colIndex]);
                }
            }
        }
        return cipher.toString();
    }

    /**
     * Decrypts the text using a Columnar Transposition Cipher.
     */
    public static String transpositionDecrypt(String cipher, int[] key) {
        validateTranspositionKey(key);

        int numCols = key.length;
        int numRows = (cipher.length() + numCols - 1) / numCols; // ceiling division
        int totalCells = numCols * numRows;
        int numShadedBoxes = totalCells - cipher.length();

        // Determine how many chars in each column
        // Full columns: those that have numRows characters
        // "Short" columns: have numRows - 1 if they are after the "fullCols" count
        int fullCols = numCols - numShadedBoxes;  // columns that get the full row count
        int[] colLengths = new int[numCols];
        for (int i = 0; i < numCols; i++) {
            if (i < fullCols) {
                colLengths[i] = numRows;
            } else {
                colLengths[i] = numRows - 1;
            }
        }

        // Get the order of columns from the key (sorted by their position)
        Integer[] colOrder = new Integer[numCols];
        for (int i = 0; i < numCols; i++) {
            colOrder[i] = i;
        }
        Arrays.sort(colOrder, (i, j) -> Integer.compare(key[i], key[j]));

        // Rebuild each column string from the cipher in sorted order
        // Then place it back according to the original column index
        String[] cols = new String[numCols];
        int currentPos = 0;
        for (int colIndex : colOrder) {
            int length = colLengths[colIndex];
            cols[colIndex] = cipher.substring(currentPos, currentPos + length);
            currentPos += length;
        }

        // Reconstruct the plaintext by reading row-by-row across the columns
        StringBuilder plaintext = new StringBuilder();
        for (int r = 0; r < numRows; r++) {
            for (int c = 0; c < numCols; c++) {
                String colString = cols[c];
                if (r < colString.length()) {
                    plaintext.append(colString.charAt(r));
                }
            }
        }
        return plaintext.toString();
    }

    // ----- Product Cipher (Affine then Transposition) -----

    /**
     * Applies Affine Cipher encryption followed by Columnar Transposition encryption.
     * Returns the intermediate Affine text and the final transposition text.
     */
    public static String[] productCipherEncrypt(String text, int a, int b, int[] key) {
        String affineEncrypted = affineEncrypt(text, a, b);
        String transpositionEncrypted = transpositionEncrypt(affineEncrypted, key);
        return new String[]{affineEncrypted, transpositionEncrypted};
    }

    /**
     * Applies the reverse process: Transposition decryption, then Affine decryption.
     */
    public static String productCipherDecrypt(String cipher, int a, int b, int[] key) {
        String transpositionDecrypted = transpositionDecrypt(cipher, key);
        return affineDecrypt(transpositionDecrypted, a, b);
    }

    // ----- Main (Example Usage) -----
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter text to encrypt: ");
        String text = sc.nextLine();

        System.out.print("Enter value for 'a' (must be coprime with 26): ");
        int affineA = sc.nextInt();

        System.out.print("Enter value for 'b': ");
        int affineB = sc.nextInt();

        sc.nextLine();  // consume leftover newline
        System.out.print("Enter transposition key (comma-separated numbers): ");
        String keyLine = sc.nextLine();
        String[] keyParts = keyLine.split(",");
        int[] transpositionKey = new int[keyParts.length];
        for (int i = 0; i < keyParts.length; i++) {
            transpositionKey[i] = Integer.parseInt(keyParts[i].trim());
        }

        try {
            // ----- Affine Cipher Timing -----
            long start = System.nanoTime();
            String affineEncrypted = affineEncrypt(text, affineA, affineB);
            long end = System.nanoTime();
            double affineEncryptTime = (end - start) / 1e9;

            start = System.nanoTime();
            String affineDecrypted = affineDecrypt(affineEncrypted, affineA, affineB);
            end = System.nanoTime();
            double affineDecryptTime = (end - start) / 1e9;

            // ----- Columnar Transposition Timing (directly on original text) -----
            start = System.nanoTime();
            String transEncrypted = transpositionEncrypt(text, transpositionKey);
            end = System.nanoTime();
            double transEncryptTime = (end - start) / 1e9;

            start = System.nanoTime();
            String transDecrypted = transpositionDecrypt(transEncrypted, transpositionKey);
            end = System.nanoTime();
            double transDecryptTime = (end - start) / 1e9;

            // ----- Product Cipher Timing (Affine then Transposition) -----
            start = System.nanoTime();
            String[] productEncryptResult = productCipherEncrypt(text, affineA, affineB, transpositionKey);
            String productEncrypted = productEncryptResult[1];  // The final transposition result
            end = System.nanoTime();
            double productEncryptTime = (end - start) / 1e9;

            start = System.nanoTime();
            String productDecrypted = productCipherDecrypt(productEncrypted, affineA, affineB, transpositionKey);
            end = System.nanoTime();
            double productDecryptTime = (end - start) / 1e9;

            // ----- Output results -----
            System.out.println("\nAffine Cipher");
            System.out.println("Encrypted: " + affineEncrypted);
            System.out.println("Decrypted: " + affineDecrypted);
            System.out.printf("Encryption Time: %.6f seconds%n", affineEncryptTime);
            System.out.printf("Decryption Time: %.6f seconds%n", affineDecryptTime);

            System.out.println("\nColumnar Transposition Cipher");
            System.out.println("Encrypted: " + transEncrypted);
            System.out.println("Decrypted: " + transDecrypted);
            System.out.printf("Encryption Time: %.6f seconds%n", transEncryptTime);
            System.out.printf("Decryption Time: %.6f seconds%n", transDecryptTime);

            System.out.println("\nProduct Cipher (Affine then Transposition)");
            System.out.println("Encrypted: " + productEncrypted);
            System.out.println("Decrypted: " + productDecrypted);
            System.out.printf("Encryption Time: %.6f seconds%n", productEncryptTime);
            System.out.printf("Decryption Time: %.6f seconds%n", productDecryptTime);

        } catch (IllegalArgumentException e) {
            // Catch any validation errors (e.g. gcd not 1 or invalid key)
            System.out.println("Error: " + e.getMessage());
        }

        sc.close();
    }
}
