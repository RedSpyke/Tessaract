package com.licenta.tessaract;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.Objects;

public class TessaractApplication extends Application {
    public static void main(String[] args) {
        boolean applicationConnectedToDatabase;
        JDBC.getConnection(); // Establish connection to database
        applicationConnectedToDatabase = JDBC.checkConnection(); // Check if connection to database was established
        if (applicationConnectedToDatabase) {
            launch();
        } else {
            // TO DO: Display error message in a new window, application cannot connect to database
        }
    }

    // TO DO: Hash of encrypted files

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(TessaractApplication.class.getResource("StartApplicationScene.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 700, 400);
        stage.setTitle("Tessaract");
        stage.setResizable(false);
        stage.setScene(scene);
        stage.getIcons().add(new Image("D:\\Drive\\Licenta UTM\\Tesseract\\Tessaract\\src\\main\\resources\\com\\licenta\\tessaract\\LogoMain.png"));
        String css = Objects.requireNonNull(getClass().getResource("/com/licenta/tessaract/styleScenes.css")).toExternalForm();
        scene.getStylesheets().add(css);
        stage.show();
    }
}