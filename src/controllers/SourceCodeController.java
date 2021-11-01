package controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.*;


public class SourceCodeController {

    private static String text;
    private static File file;

    @FXML
    private TextArea sourceCodeTextArea;

    @FXML
    private void initialize(){
        sourceCodeTextArea.setText(text);
    }

    static void setText(byte[] bytes){
        text = new String(bytes);
    }

    static void setFile(File f){
        file = f;
    }

    @FXML
    void closeButtonAction(ActionEvent event) {
        close();
    }

    private void close(){
        ((Stage)sourceCodeTextArea.getScene().getWindow()).close();
    }

    @FXML
    void compileAndRunButtonAction(ActionEvent event) {
        compileAndRun();
    }

    private void compileAndRun() {
        new Thread(){
            public void run(){
                try {
                    if("\\".equals(File.separator))
                        Runtime.getRuntime().exec("cmd /c start cmd.exe /K");
                    else
                        Runtime.getRuntime().exec("gnome-terminal");
                } catch(IOException e){
                    e.printStackTrace();
                }
            }
        }.start();
    }
}