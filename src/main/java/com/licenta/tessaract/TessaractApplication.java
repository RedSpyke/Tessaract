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
        launch();
    }

    // TO DO: Hash of encrypted files
    //


    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(TessaractApplication.class.getResource("StartApplicationScene.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 400, 400);
        stage.setTitle("Tessaract");
        stage.setScene(scene);
        stage.getIcons().add(new Image("D:\\Drive\\Licenta UTM\\Tesseract\\Tessaract\\src\\main\\resources\\img\\LogoMain.png"));
        String css = Objects.requireNonNull(getClass().getResource("/com/licenta/tessaract/styleScenes.css")).toExternalForm();
        scene.getStylesheets().add(css);
        stage.show();
    }





}