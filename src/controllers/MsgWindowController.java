package controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.stage.Stage;


public class MsgWindowController {

    @FXML
    private Label msgLabel;

    private static String message;

    @FXML private void initialize(){
        msgLabel.setText(message);
    }

    public static void setMessage(String msg){
        message = msg;
    }

    @FXML
    void okButtonAction(ActionEvent event) {
        close();
    }
    void close(){
        ((Stage)msgLabel.getScene().getWindow()).close();
    }
}
