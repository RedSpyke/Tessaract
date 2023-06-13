package com.licenta.tessaract;

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

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.ResourceBundle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;


import static com.licenta.tessaract.JDBC.checkHashValue;

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

    private final String[] dimensiuniCheie = {"128","192","256"};
    private String selectedFilePath;

    // FXML data fields

    @FXML
    public RadioButton genereazaHashDate;
    @FXML
    public Label rezultatVerificare;
    @FXML
    public Button butonVerifica;
    @FXML
    public RadioButton butonVerificareDateScene;
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
                    TessaractApplication.emailUtilizatorLogat = email;
             //       System.out.println("Email utilizator logat: " + TessaractApplication.emailUtilizatorLogat); // TO DO delete
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
            } else if (butonVerificareDateScene.isSelected()) {
                try {
                    switchVerifyAccountScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if(genereazaHashDate.isSelected()){
                try {
                    switchCreateHashScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (butonOperatiuneCriptareKey.isSelected()) {
                try {
                    switchKeyBasedEncryptionScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else if (ButonOperatiuneDecriptareKey.isSelected()) {
                try {
                    switchKeyBasedDecryptionScene(event);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
    }

    // Method to add a file in the encryption scene when adauga DocumentButton is clicked (TO DO)
    @FXML
    private void addDocumentButton() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Selectati Document");
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
    private void verificaIntegritareDate() {
        // Get the file name from the text field
        String fileName = numeDocument.getText();
        System.out.println("Nume document: " + fileName);
        String email = TessaractApplication.emailUtilizatorLogat;
        System.out.println("Email utilizator logat: " + email);

        String filePath = selectedFilePath;
        if (filePath == null || filePath.isEmpty()) {
            rezultatVerificare.setText("Niciun fisier selectat.");
            return;
        }
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            rezultatVerificare.setText("Fișierul nu a fost găsit.");
        }

        String hash = generateHashFunction(filePath.getBytes());
        System.out.println("Hash: " + hash);
        boolean dateValide = JDBC.checkHashValue(email, fileName, hash);
        if (dateValide) {
            rezultatVerificare.setText("Datele nu au fost modificate!");
        } else {
            rezultatVerificare.setText("Datele au fost modificate!");
        }
    }

    @FXML
    private void creazaValoareHash(){
        // Get the file name from the text field
        String fileName = numeDocument.getText();
        System.out.println("Nume document: " + fileName);
        String email = TessaractApplication.emailUtilizatorLogat;
        System.out.println("Email utilizator logat: " + email);

        String filePath = selectedFilePath;
        if (filePath == null || filePath.isEmpty()) {
            rezultatVerificare.setText("Fisierul nu a fost găsit.");
            return;
        }
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            rezultatVerificare.setText("Fisierul nu a fost găsit.");
        }
        String hash = generateHashFunction(filePath.getBytes());
        JDBC.writeHashValue(email, fileName, hash);
    }

    private String generateHashFunction(byte[] encryptedData) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashValue = md.digest(encryptedData);
            StringBuilder sb = new StringBuilder();
            for (byte b : hashValue) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    @FXML
    private void encryptButton() {
        String filePath = selectedFilePath;
        if (filePath == null || filePath.isEmpty()) {
            encryptionStatusLabel.setText("Niciun fisier selectat.");
            return;
        }
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            encryptionStatusLabel.setText("Fisierul nu a fost găsit.");
            return;
        }
        String password = parolaCheie.getText();
        if (password.isEmpty()) {
            encryptionStatusLabel.setText("Parola este necesara.");
            return;
        }
        int keySize;
        String algorithm = getSelectedAlgorithm();
        if(algorithm == null){
            encryptionStatusLabel.setText("Algoritmul nu a fost selectat.");
            return;
        }

        if ("CAST5".equals(algorithm)) {
            keySize = 128;
            Security.addProvider(new BouncyCastleProvider());
        } else {
            String keySizeString = comboBoxCheie.getValue();
            if(keySizeString == null){
                encryptionStatusLabel.setText("Dimensiunea cheii nu a fost selectata.");
                return;
            } else {
                keySize = Integer.parseInt(keySizeString);
            }

        }
        try{
            if (algorithm.equals("AES")){
                    // Generate a salt
                    byte[] salt = generateSalt();
                    // Generate a key using PBKDF2
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
                    SecretKey key = null;
                    key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
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
                        encryptionStatusLabel.setText("Criptarea finalizată. Fișier criptat salvat.");
                    } else {
                        encryptionStatusLabel.setText("Criptarea a fost anulată.");
                    }
            }
            else if (algorithm.equals("Blowfish")) {
                // Generate a secret key using the password
                SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "Blowfish");

                // Create a cipher object with Blowfish algorithm
                Cipher cipher = Cipher.getInstance("Blowfish");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                // Read the contents of the input file
                byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

                // Encrypt the input bytes
                byte[] encryptedBytes = cipher.doFinal(inputBytes);

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
                    Files.write(outputFile.toPath(), encryptedBytes);
                    encryptionStatusLabel.setText("Criptarea finalizată. Fișier criptat salvat.");
                } else {
                    encryptionStatusLabel.setText("Criptarea a fost anulată.");
                }
            }
            else if (algorithm.equals("CAST5")){
                byte[] salt = generateSalt();

                // Generate a key using PBKDF2
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);

                // Create a cipher object with the CAST5 algorithm
                Cipher cipher = Cipher.getInstance("CAST5/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);

                // Read the contents of the input file
                byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

                // Encrypt the input bytes
                byte[] encryptedBytes = cipher.doFinal(inputBytes);

                // Combine salt and encrypted bytes
                ByteBuffer encryptedBuffer = ByteBuffer.allocate(salt.length + cipher.getIV().length + encryptedBytes.length);
                encryptedBuffer.put(salt);
                encryptedBuffer.put(cipher.getIV());
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
                    encryptionStatusLabel.setText("Criptarea finalizată. Fișier criptat salvat.");
                } else {
                    encryptionStatusLabel.setText("Criptarea a fost anulată.");
                }
            }
            else {
                encryptionStatusLabel.setText("Vă rugăm să selectați un algoritm.");
            }
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
               InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException e){
            encryptionStatusLabel.setText("Criptarea a eșuat: " + e.getMessage());
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
            encryptionStatusLabel.setText("Niciun fisier selectat.");
            return;
        }
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            encryptionStatusLabel.setText("Fișierul nu a fost găsit.");
            return;
        }
        String password = parolaCheie.getText();
        if (password.isEmpty()) {
            encryptionStatusLabel.setText("Parola este necesara.");
            return;
        }

        int keySize;
        String algorithm = getSelectedAlgorithm();
        if(algorithm == null) {
            encryptionStatusLabel.setText("Vă rugăm să selectați un algoritm.");
            return;
        }

        if ("CAST5".equals(algorithm)) {
            keySize = 128;
            Security.addProvider(new BouncyCastleProvider());
        } else {
            String keySizeString = comboBoxCheieDecriptare.getValue();
         //   System.out.println(keySizeString);
            if(keySizeString == null || keySizeString.isEmpty()) {
                encryptionStatusLabel.setText("Vă rugăm să selectați o dimensiune a cheii.");
                return;
            } else {
                keySize = Integer.parseInt(keySizeString);
            }
        }
        try {
            if(algorithm.equals("AES")) {
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
                    encryptionStatusLabel.setText("Decriptarea a fost finalizată. Fișier decriptat salvat.");
                } else {
                    encryptionStatusLabel.setText("Decriptarea a fost anulată.");
                }
            }
            else if (algorithm.equals("Blowfish")) {
                // Generate a key using the password
                SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "Blowfish");

                // Create a cipher object with the Blowfish algorithm
                Cipher cipher = Cipher.getInstance("Blowfish");
                cipher.init(Cipher.DECRYPT_MODE, keySpec);

                // Read the contents of the encrypted file
                byte[] encryptedBytes = Files.readAllBytes(inputFile.toPath());

                // Decrypt the encrypted bytes
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

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
                    encryptionStatusLabel.setText("Decriptarea a fost finalizată. Fișier decriptat salvat.");
                } else {
                    encryptionStatusLabel.setText("Decriptarea a fost anulată.");
                }
            }
            else if (algorithm.equals("CAST5")){
                // Read the contents of the encrypted file
                byte[] encryptedBytes = Files.readAllBytes(inputFile.toPath());

                // Extract the salt, IV, and encrypted data from the encrypted bytes
                byte[] salt = Arrays.copyOfRange(encryptedBytes, 0, 16);
                byte[] ivBytes = Arrays.copyOfRange(encryptedBytes, 16, 24);
                byte[] encryptedData = Arrays.copyOfRange(encryptedBytes, 24, encryptedBytes.length);

                // Generate a key using PBKDF2
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);

                // Create a cipher object with the CAST5 algorithm
                Cipher cipher = Cipher.getInstance("CAST5/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
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
                    encryptionStatusLabel.setText("Decriptarea a fost finalizată. Fișier decriptat salvat.");
                } else {
                    encryptionStatusLabel.setText("Decriptarea a fost anulată.");
                }
            }
            else {
                encryptionStatusLabel.setText("Vă rugăm să selectați un algoritm.");
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | IOException e) {
            encryptionStatusLabel.setText("Decriptarea a eșuat: " + e.getMessage());
        }
    }
    @FXML
    private void keyBasedEncryption(){
        // to do
    }

    @FXML
    private void keyBasedDecryption(){
        // to do
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
    @FXML
    private void switchVerifyAccountScene(ActionEvent event) throws IOException {
        switchScene("DataIntegrityVerifier.fxml", event);
    }
    @FXML
    private void switchCreateHashScene(ActionEvent event) throws IOException {
        switchScene("generateHashValueData.fxml", event);
    }
    @FXML
    private void switchKeyBasedEncryptionScene(ActionEvent event) throws IOException {
        switchScene("keyEncryptScene.fxml", event);
    }
    @FXML
    private void switchKeyBasedDecryptionScene(ActionEvent event) throws IOException {
        switchScene("keyDecryptScene.fxml", event);
    }


}
