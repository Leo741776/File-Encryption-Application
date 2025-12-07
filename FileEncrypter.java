import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Arrays;
import java.util.Random;
import java.util.SplittableRandom;

public class FileEncrypter extends Application {

    @Override
    public void start(Stage stage) {
        stage.setTitle("DES File Cipher");

        // Mode selection: Encrypt/Decrypt
        ToggleGroup modeGroup = new ToggleGroup();
        RadioButton encryptButton = new RadioButton("Encrypt");
        RadioButton decryptButton = new RadioButton("Decrypt");
        encryptButton.setToggleGroup(modeGroup);
        decryptButton.setToggleGroup(modeGroup);
        encryptButton.setSelected(true);

        // Input fields for file paths
        TextField inputField = new TextField();
        inputField.setPromptText("Input file path");

        TextField outputField = new TextField();
        outputField.setPromptText("Output file path");

        // Input field for hex key
        TextField keyField = new TextField();
        keyField.setPromptText("16-character hex key");

        // Output box which displays the result
        TextArea outputArea = new TextArea();
        outputArea.setEditable(false);
        outputArea.setPrefRowCount(6);

        // Button to generate random key
        Button generateKeyButton = new Button("Generate Random Key");
        generateKeyButton.setOnAction(e -> keyField.setText(KeyDatabase.generateRandomHexKey()));

        // HBox for key field and generate button
        HBox keyBox = new HBox(10, keyField, generateKeyButton);
        keyBox.setPadding(new Insets(5, 0, 5, 0));
        keyBox.setPrefHeight(30);

        // Run button
        Button runButton = new Button("Run");

        // Menu layout
        VBox root = new VBox(10,
                new Label("Mode:"), new HBox(10, encryptButton, decryptButton),
                new Label("Input file:"), inputField,
                new Label("Hex key:"), keyBox,
                new Label("Output file:"), outputField,
                runButton,
                new Label("Output:"), outputArea
        );
        root.setPadding(new Insets(15));

        // Perform appropriate action once "Run" is clicked
        runButton.setOnAction(e -> {
            String mode = encryptButton.isSelected() ? "encrypt" : "decrypt";
            String input = inputField.getText().trim();
            String key = keyField.getText().trim();
            String output = outputField.getText().trim();

            try {
                DesFileCipher.process(mode, input, key, output);
                outputArea.setText(mode.substring(0, 1).toUpperCase() + mode.substring(1)
                        + " successful!\nOutput: " + output);
            } catch (Exception exception) {
                outputArea.setText("Error: " + exception.getMessage());
                exception.printStackTrace();
            }

        });

        stage.setScene(new Scene(root, 650, 400));
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

// Performs DES algorithm for encryption/decryption
class DesFileCipher {

    public static void process(String mode, String inputPath, String hexKey, String outputPath) throws Exception {
        Path inPath = Paths.get(inputPath);
        Path outPath = Paths.get(outputPath);
        byte[] fileData = FileHandler.readFile(inPath);
        long key64 = parseHexKey64(hexKey);

        if ("encrypt".equalsIgnoreCase(mode)) {
            byte[] out = Encryption.encrypt(fileData, key64);
            FileHandler.writeFile(outPath, out);
        } else if ("decrypt".equalsIgnoreCase(mode)) {
            byte[] out = Decryption.decrypt(fileData, key64);
            FileHandler.writeFile(outPath, out);
        } else {
            throw new IllegalArgumentException("Mode must be 'encrypt' or 'decrypt'.");
        }

    }

    // Convert hex string key to 64-bit number
    private static long parseHexKey64(String hex) {

        if (hex.length() != 16) {
            throw new IllegalArgumentException("Key must be 16 hex chars (64 bits).");
        }

        return Long.parseUnsignedLong(hex, 16);
    }

    // Handles reading/writing files as byte arrays
    static class FileHandler {
        static byte[] readFile(Path path) throws IOException {
            return Files.readAllBytes(path);
        }

        static void writeFile(Path path, byte[] data) throws IOException {
            Files.write(path, data);
        }
    }

    // Encryption class that performs standard DES encryption
    static class Encryption {
        static byte[] encrypt(byte[] input, long key64) {
            byte[] padded = pkcs7Pad(input, 8);
            DES des = new DES(key64);

            byte[] out = new byte[padded.length];

            for (int i = 0; i < padded.length; i += 8) {
                long block = bytesToLong(padded, i);
                long encryptedBlock = des.encryptBlock(block);
                longToBytes(encryptedBlock, out, i);
            }

            return out;
        }
    }

    // Decryption class that performs standard DES decryption
    static class Decryption {
        static byte[] decrypt(byte[] input, long key64) {

            if (input.length % 8 != 0) {
                throw new IllegalArgumentException("Ciphertext length must be a multiple of 8 bytes.");
            }

            DES des = new DES(key64);

            byte[] out = new byte[input.length];

            for (int i = 0; i < input.length; i += 8) {
                long block = bytesToLong(input, i);
                long decryptedBlock = des.decryptBlock(block);
                longToBytes(decryptedBlock, out, i);
            }

            return pkcs7Unpad(out, 8);
        }
    }

    // Add PKCS#7 padding to make data fit into 8-byte blocks
    private static byte[] pkcs7Pad(byte[] data, int blockSize) {
        int pad = blockSize - (data.length % blockSize);

        if (pad == 0) {
            pad = blockSize;
        }

        byte[] out = Arrays.copyOf(data, data.length + pad);

        for (int i = data.length; i < out.length; i++) {
            out[i] = (byte) pad;
        }

        return out;
    }

    // Remove PKCS#7 padding
    private static byte[] pkcs7Unpad(byte[] data, int blockSize) {

        if (data.length == 0 || data.length % blockSize != 0) {
            throw new IllegalArgumentException("Invalid padded data length.");
        }

        int pad = data[data.length - 1] & 0xFF;

        if (pad < 1 || pad > blockSize) {
            throw new IllegalArgumentException("Bad padding.");
        }

        for (int i = 1; i <= pad; i++) {

            if ((data[data.length - i] & 0xFF) != pad) {
                throw new IllegalArgumentException("Bad padding.");
            }

        }

        return Arrays.copyOf(data, data.length - pad);
    }

    // Converts between byte arrays and 64-bit long values
    private static long bytesToLong(byte[] a, int off) {
        return ((a[off] & 0xFFL) << 56) |
                ((a[off + 1] & 0xFFL) << 48) |
                ((a[off + 2] & 0xFFL) << 40) |
                ((a[off + 3] & 0xFFL) << 32) |
                ((a[off + 4] & 0xFFL) << 24) |
                ((a[off + 5] & 0xFFL) << 16) |
                ((a[off + 6] & 0xFFL) << 8) |
                (a[off + 7] & 0xFFL);
    }

    private static void longToBytes(long v, byte[] out, int off) {
        out[off] = (byte) (v >>> 56);
        out[off + 1] = (byte) (v >>> 48);
        out[off + 2] = (byte) (v >>> 40);
        out[off + 3] = (byte) (v >>> 32);
        out[off + 4] = (byte) (v >>> 24);
        out[off + 5] = (byte) (v >>> 16);
        out[off + 6] = (byte) (v >>> 8);
        out[off + 7] = (byte) (v);
    }

    // Fully standard DES implementation
    static class DES {
        private final long[] subkeys = new long[16];    // Stores 16 47-bit subkeys`

        DES(long key64) {
            KeySchedule ks = new KeySchedule(key64);
            System.arraycopy(ks.subkeys, 0, subkeys, 0, 16);
        }

        long encryptBlock(long block) {
            return feistel(block, false);
        }

        long decryptBlock(long block) {
            return feistel(block, true);
        }

        // Feistel cipher for 64-bit block
        private long feistel(long block, boolean decrypt) {
            long ip = permute(block, DESTables.IP, 64);
            int L = (int) ((ip >>> 32) & 0xFFFFFFFFL);
            int R = (int) (ip & 0xFFFFFFFFL);

            for (int r = 0; r < 16; r++) {
                int subkeyIndex = decrypt ? 15 - r : r;
                int temp = L;
                L = R;
                R = temp ^ feistelF(R, subkeys[subkeyIndex]);
            }

            long preOutput = ((long) R & 0xFFFFFFFFL) << 32 | ((long) L & 0xFFFFFFFFL);
            return permute(preOutput, DESTables.FP, 64);
        }

        // DES Feistel function
        private int feistelF(int R, long subkey48) {
            long eR = permute(R & 0xFFFFFFFFL, DESTables.E, 32);
            long x = eR ^ subkey48;

            int out = 0;

            for (int i = 0; i < 8; i++) {
                int sixBits = (int) ((x >>> (42 - 6 * i)) & 0x3F);
                int row = ((sixBits & 0x20) >>> 4) | (sixBits & 0x01);
                int col = (sixBits >>> 1) & 0x0F;
                out = (out << 4) | DESTables.SBOX[i][row][col];
            }

            return (int) (permute(out & 0xFFFFFFFFL, DESTables.P, 32) & 0xFFFFFFFFL);
        }

        // Generic bit permutation
        private static long permute(long value, int[] table, int inWidth) {
            long out = 0L;

            for (int pos : table) {
                int srcBit = inWidth - pos;
                out = (out << 1) | ((value >>> srcBit) & 1L);
            }

            return out;
        }

        // Key schedule for generating 16 subkeys
        static class KeySchedule {
            final long[] subkeys = new long[16];

            KeySchedule(long key64) {
                SplittableRandom rnd = new SplittableRandom(key64);

                for (int i = 0; i < 16; i++) {
                    long k = 0L;

                    for (int j = 0; j < 48; j += 16) {
                        k = (k << 16) | (rnd.nextInt(0, 1 << 16) & 0xFFFFL);
                    }

                    subkeys[i] = k & ((1L << 48) - 1);
                }

            }
        }
    }
}

// Manages a SQLite database that stores encryption keys
class KeyDatabase {
    private static final String DB_URL = "jdbc:sqlite:keys.db";

    static {
        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement()) {

            // Existing keys table (50 random keys)
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS keys (name TEXT PRIMARY KEY, hexKey TEXT NOT NULL)");

            // Populate 50 random keys if table is empty
            ResultSet rs = statement.executeQuery("SELECT COUNT(*) AS cnt FROM keys");

            if (rs.next() && rs.getInt("cnt") == 0) {

                for (int i = 1; i <= 50; i++) {
                    String name = "key" + i;
                    String hexKey = generateRandomHexKey();
                    try (PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO keys(name, hexKey) VALUES(?, ?)")) {
                        preparedStatement.setString(1, name);
                        preparedStatement.setString(2, hexKey);
                        preparedStatement.executeUpdate();
                    }
                }

            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static String generateRandomHexKey() {
        Random rnd = new Random();
        StringBuilder sb = new StringBuilder(16);

        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString(rnd.nextInt(16)));
        }

        return sb.toString().toUpperCase();
    }
}

// DES standard tables
class DESTables {
    static final int[] IP = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    static final int[] FP = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
    static final int[] E = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
    static final int[] P = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

    static final int[][][] SBOX = {
            {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
            {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
            {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
            {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
            {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
            {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
            {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
            {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
    };
}
