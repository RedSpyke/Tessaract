package com.licenta.tessaract;

import javafx.animation.PauseTransition;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.ResourceBundle;



// TO DO Validare metode

public class FxController implements Initializable {


    @FXML
    private Stage stage = new Stage();

    @Override
    public void initialize(URL args0, ResourceBundle args1) {
        comboBoxCheieDecriptare.getItems().addAll(dimensiuniCheie);
        comboBoxCheie.getItems().addAll(dimensiuniCheie);
    }

    // Data fields
    private String numeUtilizatorLogat;

    private final String[] dimensiuniCheie = {"128","192","256"};
    private String selectedFilePath;

    // FXML data fields
    @FXML
    public RadioButton blowfishRadioButton;
    @FXML
    public RadioButton cast5RadioButton;
    @FXML
    public RadioButton AESRadioButton;
    @FXML
    public RadioButton ButonOperatiuneDecriptareKey;
    @FXML
    public RadioButton butonOperatiuneCriptareKey;
    @FXML
    public RadioButton butonVerificareDate;
    @FXML
    public ComboBox <String>comboBoxCheieDecriptare = new ComboBox<>();
    @FXML
    public ComboBox <String> comboBoxCheie = new ComboBox<>();
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
    protected void onLogInButtonClicked(ActionEvent event) throws IOException, NoSuchAlgorithmException {
          //  String validEmail = "admin@gmail.com";
          //  String validPass = "Pass1234ote!";
            String email = emailField.getText();
            String password = passwordField.getText();

            if(!User.isValidEmail(email)){
                loginResultText.setText("Adresa de email invalida!");
                resetTextFields();
            } else if (!User.validatePassword(password)) {
                loginResultText.setText("Parola invalida!");
                resetTextFields();
            } else{
                if(JDBC.authenticateUser(email, password)){
                    loginResultText.setText("Autentificare reusita!");
                    numeUtilizatorLogat = JDBC.retrieveUserName(email);
                    switchMainApplicationScene(event);
                } else {
                    loginResultText.setText("Autentificare esuata!");
                }
            }
    }
    private void resetTextFields() {
        emailField.setText("");
        passwordField.setText("");
    }
    @FXML
    protected void onCreateAccountButtonClicked(ActionEvent event) throws IOException {
        switchCreateAccountScene(event);
    }

    @FXML
    private void onCreateNewAccountButtonClicked(ActionEvent event) throws NoSuchAlgorithmException, IOException {
        String userName = newUserName.getText();
        String userEmail = newEmailAddress.getText();
        String userAccountPassword = newAccountPassword.getText();
        // TO DO check if email already exists in database
        // TO DO check if password was already used for the account in database

        if(!User.isValidEmail(userEmail)){
            userDetails.setText("Adresa de email invalida!");
            resetTextFields();
        } else if (!User.validatePassword(userAccountPassword)) {
            userDetails.setText("Parola invalida!");
            resetTextFields();
        } else{
            if (JDBC.createUser(userName, userEmail, userAccountPassword)){
                userDetails.setText("Contul a fost creat cu succes!");
                newUserName.setText("");
                newEmailAddress.setText("");
                newAccountPassword.setText("");
            } else {
                userDetails.setText("Contul nu a putut fi creat!");
            }
        }
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

    // Method to add a file in the encryption scene when adauga DocumentButton is clicked (TO DO)
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

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
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
        String password = parolaCheie.getText();
        if (password.isEmpty()) {
            encryptionStatusLabel.setText("Password is required.");
            return;
        }
        int keySize;
        String algorithm = getSelectedAlgorithm();
        if ("CAST5".equals(algorithm)) {
            keySize = 128;
        } else {
            keySize = Integer.parseInt(comboBoxCheie.getValue());
        }
        try {
            // Generate a salt
            byte[] salt = generateSalt();

            // Generate a key using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
            SecretKey key = null;
            if (algorithm != null) {
                key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
            }

            // Generate an initialization vector (IV)
            SecureRandom ivRandom = new SecureRandom();
            byte[] ivBytes = new byte[12];
            ivRandom.nextBytes(ivBytes);
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);

            // Create a cipher object in GCM mode with the chosen algorithm
            Cipher cipher = Cipher.getInstance(algorithm + "/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            // Read the contents of the input file
            byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

            // Encrypt the input bytes
            byte[] encryptedBytes = cipher.doFinal(inputBytes);

            // Combine salt, IV, and encrypted bytes
            ByteBuffer encryptedBuffer = ByteBuffer.allocate(salt.length + ivBytes.length + encryptedBytes.length);
            encryptedBuffer.put(salt);
            encryptedBuffer.put(ivBytes);
            encryptedBuffer.put(encryptedBytes);
            byte[] encryptedData = encryptedBuffer.array();

            // Get the file name without extension
            String fileName = inputFile.getName();
            int extensionIndex = fileName.lastIndexOf(".");
            String fileNameWithoutExtension = (extensionIndex != -1) ? fileName.substring(0, extensionIndex) : fileName;

            // Create the encrypted file name
            String encryptedFileName = fileNameWithoutExtension + "_encrypted" + getOriginalFileExtension(fileName);

            // Save the encrypted file
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Encrypted File");
            fileChooser.setInitialFileName(encryptedFileName);
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Binary Files", "*.bin"));
            File outputFile = fileChooser.showSaveDialog(new Stage());
            if (outputFile != null) {
                Files.write(outputFile.toPath(), encryptedData);
                encryptionStatusLabel.setText("Encryption completed. Encrypted file saved.");
            } else {
                encryptionStatusLabel.setText("Encryption canceled.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            encryptionStatusLabel.setText("Encryption failed: " + e.getMessage());
        }
    }


    private String getSelectedAlgorithm() {
        if (AESRadioButton.isSelected()) {
            return "AES";
        } else if (blowfishRadioButton.isSelected()) {
            return "Blowfish";
        } else if (cast5RadioButton.isSelected()) {
            return "CAST5";
        } else {
            return null;
        }
    }

    @FXML
    private void decryptionButton() {
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
        String password = parolaCheie.getText();
        if (password.isEmpty()) {
            encryptionStatusLabel.setText("Password is required.");
            return;
        }

        int keySize;
        String algorithm = getSelectedAlgorithm();
        if ("CAST5".equals(algorithm)) {
            keySize = 128;
        } else {
            keySize = Integer.parseInt(comboBoxCheieDecriptare.getValue());
        }
        try {
            // Read the contents of the encrypted file
            byte[] encryptedBytes = Files.readAllBytes(inputFile.toPath());

            // Extract the salt, IV, and encrypted data from the encrypted bytes
            byte[] salt = Arrays.copyOfRange(encryptedBytes, 0, 16);
            byte[] ivBytes = Arrays.copyOfRange(encryptedBytes, 16, 28);
            byte[] encryptedData = Arrays.copyOfRange(encryptedBytes, 28, encryptedBytes.length);

            // Generate a key using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);

            // Create a cipher object in GCM mode with the chosen algorithm
            Cipher cipher = Cipher.getInstance(algorithm + "/GCM/NoPadding");
            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            // Decrypt the encrypted bytes
            byte[] decryptedBytes = cipher.doFinal(encryptedData);

            // Get the file name without extension
            String fileName = inputFile.getName();
            int extensionIndex = fileName.lastIndexOf(".");
            String fileNameWithoutExtension = (extensionIndex != -1) ? fileName.substring(0, extensionIndex) : fileName;

            // Create the decrypted file name
            String decryptedFileName = fileNameWithoutExtension + "_decrypted" + getOriginalFileExtension(fileName);

            // Save the decrypted file
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Decrypted File");
            fileChooser.setInitialFileName(decryptedFileName);
            fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All Files", "*.*"));
            File outputFile = fileChooser.showSaveDialog(new Stage());
            if (outputFile != null) {
                Files.write(outputFile.toPath(), decryptedBytes);
                encryptionStatusLabel.setText("Decryption completed. Decrypted file saved.");
            } else {
                encryptionStatusLabel.setText("Decryption canceled.");
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            encryptionStatusLabel.setText("Decryption failed: " + e.getMessage());
        }
    }
    private String getOriginalFileExtension(String fileName) {
        int extensionIndex = fileName.lastIndexOf(".");
        return (extensionIndex != -1) ? fileName.substring(extensionIndex) : "";
    }

    private void switchScene(String fxmlFileName, ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource(fxmlFileName)));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
    @FXML
    private void switchEncryptScene(ActionEvent event) throws IOException {
        switchScene("EncryptionScene.fxml", event);
    }
    @FXML
    private void switchDecryptScene(ActionEvent event) throws IOException {
        switchScene("DecryptionScene.fxml", event);
    }
    @FXML
    private void switchMainApplicationScene(ActionEvent event) throws IOException {
        switchScene("MainApplicationScene.fxml", event);
    }
    @FXML
    private void switchCreateAccountScene(ActionEvent event) throws IOException {
        switchScene("CreateAccountScene.fxml", event);
    }
    @FXML
    private void switchStartApplicationScene(ActionEvent event) throws IOException {
        switchScene("StartApplicationScene.fxml", event);
    }

}
