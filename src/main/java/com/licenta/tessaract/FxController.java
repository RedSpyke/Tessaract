package com.licenta.tessaract;

import javafx.animation.PauseTransition;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

// TO DO Validare metode

public class FxController {



    // Data fields
    private String selectedFilePath;

    // FXML data fields
    @FXML
    public TextField parolaCheie;
    @FXML
    public Label alegeOperatiune;
    @FXML
    public Button adaugaCheie;
    @FXML
    private Label encryptionStatusLabel;
    @FXML
    public Label userDetails;
    @FXML
    public RadioButton butonOperatiuneCriptare;
    @FXML
    public RadioButton ButonOperatiuneDecriptare;
    @FXML
    public Button butonContinuaAlegereOperatiune;
    @FXML
    public ToggleGroup alegere;
    @FXML
    public Button CriptareDocumentButton;
    @FXML
    public Button adaugaDocumentButton;
    public TextField numeDocument;
    @FXML
    private PasswordField newAccountPassword;
    @FXML
    private Button createNewAccountButton;
    @FXML
    private TextField newEmailAddress;
    @FXML
    private TextField newUserName;
    private Stage stage;
    private Scene scene;
    @FXML
    private Label loginResultText;
    @FXML
    private Button createAccountButton;
    @FXML
    private PasswordField passwordField;
    @FXML
    private TextField emailField;

    @FXML
    protected void onLogInButtonClicked(ActionEvent event) throws IOException {

        String validEmail = "admin@gmail.com";
        String validPass = "Pass1234!";
        String email = emailField.getText();
        String password = passwordField.getText();

        // Example: Check if email and password are valid
        if (validEmail.equals(email) && validPass.equals(password)) {
            loginResultText.setText("Login successful!");
            switchMainApplicationScene(event);

        } else {
            loginResultText.setText("Parola sau adresa de email incorecta!");
        }
    }

    @FXML
    protected void onCreateAccountButtonClicked(ActionEvent event) throws IOException {
        switchCreateAccountScene(event);
    }

    @FXML
    protected String onCreateNewAccountButtonClicked(ActionEvent event) {

        String userName = newUserName.getText();
        String userEmail = newEmailAddress.getText();
        String userAccountPassword = newAccountPassword.getText();
        String newUser = userName + " " + userEmail + " " + userAccountPassword;
        userDetails.setText("User Details: " + newUser);
        PauseTransition pause = new PauseTransition(Duration.seconds(3)); // 3 seconds delay
        pause.setOnFinished(e -> {
            try {
                switchStartApplicationScene(event);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        pause.play();
        return newUser;
    }
    @FXML
    private void chooseOperationButton(ActionEvent event) {
            if (butonOperatiuneCriptare.isSelected()) {
                try {
                    switchEncryptScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (ButonOperatiuneDecriptare.isSelected()) {
                try {
                    switchDecryptScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
    }

    // Method to add a file in the encryption scene when adaugaDocumentButton is clicked (TO DO)    EncryptionScene.fxml -> adaugaDocumentButton
    @FXML
    private void addDocumentButton() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select Document");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Files", "*.*")
        );

        // Show the file chooser dialog
        File selectedFile = fileChooser.showOpenDialog(adaugaDocumentButton.getScene().getWindow());

        if (selectedFile != null) {
            String fileName = selectedFile.getName();
            numeDocument.setText(fileName);
            selectedFilePath = selectedFile.getAbsolutePath();
        }
    }

    private String encodeKey(SecretKey key) {
        byte[] keyBytes = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    @FXML
    private void encryptButton() {
        String filePath = selectedFilePath;

        if (filePath == null || filePath.isEmpty()) {
            encryptionStatusLabel.setText("No file selected.");
            return;
        }

        File inputFile = new File(filePath);

        if (!inputFile.exists()) {
            encryptionStatusLabel.setText("File not found.");
            return;
        }

        try {
            // Generate a new AES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey key = keyGenerator.generateKey();


            // Generate an initialization vector (IV)
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[12];
            random.nextBytes(ivBytes);
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);

            // Create a cipher object in GCM mode with AES algorithm
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            // Read the contents of the input file
            byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

            // Encrypt the input bytes
            byte[] encryptedBytes = cipher.doFinal(inputBytes);

            // Get the file name without extension
            String fileName = inputFile.getName();
            int extensionIndex = fileName.lastIndexOf(".");
            String fileNameWithoutExtension = (extensionIndex != -1) ? fileName.substring(0, extensionIndex) : fileName;

            // Create the encrypted file name
            String encryptedFileName = fileNameWithoutExtension + "_encrypted.bin";

            // Save the encrypted file
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Encrypted File");
            fileChooser.setInitialFileName(encryptedFileName);
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Binary Files", "*.bin"));
            File outputFile = fileChooser.showSaveDialog(new Stage());
            if (outputFile != null) {
                Files.write(outputFile.toPath(), encryptedBytes);
                encryptionStatusLabel.setText("Encryption completed. Encrypted file saved.");
            } else {
                encryptionStatusLabel.setText("Encryption canceled.");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                 IOException e) {
            encryptionStatusLabel.setText("Encryption failed: " + e.getMessage());
        }
    }
    @FXML
    private void decryptionButton() {
        String filePath = selectedFilePath;

        if (filePath == null || filePath.isEmpty()) {
            encryptionStatusLabel.setText("No file selected.");
            return;
        }

        String keyText = " "; // TO DO: Get the encryption key from the key text field
        if (keyText == null || keyText.isEmpty()) {
            encryptionStatusLabel.setText("No encryption key available.");
            return;
        }

        File inputFile = new File(filePath);

        if (!inputFile.exists()) {
            encryptionStatusLabel.setText("File not found.");
            return;
        }

        try {
            // Decode the encryption key from Base64
            byte[] keyBytes = Base64.getDecoder().decode(keyText);
            SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");

            // Generate an initialization vector (IV)
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[12];
            random.nextBytes(ivBytes);
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);

            // Create a cipher object in GCM mode with AES algorithm
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, iv);

            // Read the contents of the input file
            byte[] encryptedBytes = Files.readAllBytes(inputFile.toPath());

            // Decrypt the input bytes
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Get the file name without extension
            String fileName = inputFile.getName();
            int extensionIndex = fileName.lastIndexOf(".");
            String fileNameWithoutExtension = (extensionIndex != -1) ? fileName.substring(0, extensionIndex) : fileName;

            // Create the decrypted file name
            String decryptedFileName = fileNameWithoutExtension + "_decrypted.txt";

            // Save the decrypted file
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Decrypted File");
            fileChooser.setInitialFileName(decryptedFileName);
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
            File outputFile = fileChooser.showSaveDialog(new Stage());
            if (outputFile != null) {
                Files.write(outputFile.toPath(), decryptedBytes);
                encryptionStatusLabel.setText("Decryption completed. Decrypted file saved.");
            } else {
                encryptionStatusLabel.setText("Decryption canceled.");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                 IOException e) {
            encryptionStatusLabel.setText("Decryption failed: " + e.getMessage());
        }
    }



    private void switchEncryptScene(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("EncryptionScene.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
    private void switchDecryptScene(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("DecryptionScene.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    private void switchMainApplicationScene(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("MainApplicationScene.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    private void switchCreateAccountScene(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("CreateAccountScene.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    private void switchStartApplicationScene(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("StartApplicationScene.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
}
