module com.licenta.tessaract {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires org.kordamp.ikonli.javafx;
    requires java.sql;
    requires org.bouncycastle.provider;

    opens com.licenta.tessaract to javafx.fxml;
    exports com.licenta.tessaract;
}