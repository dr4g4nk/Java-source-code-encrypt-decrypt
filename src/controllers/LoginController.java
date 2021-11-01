package controllers;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.stage.Stage;
import util.Util;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class LoginController {

    @FXML
    private TextField username;

    @FXML
    private PasswordField password;

    @FXML
    private TextField certificateTextField;

    private ToggleGroup group = new ToggleGroup();

    @FXML
    private RadioButton encryptRadioButton;

    @FXML
    private RadioButton decryptRadioButton;

    private static File certificate;
    private static String user;
    private File users = new File("users.txt");

    @FXML
    private void initialize(){
        encryptRadioButton.setToggleGroup(group);
        encryptRadioButton.setSelected(true);
        decryptRadioButton.setToggleGroup(group);
    }

    public static File getCertificate(){
        return certificate;
    }

    static String getUser(){
        return user;
    }

    @FXML
    void addCertificateButtonAction(ActionEvent event) {
        findCertificate();
    }

    private void findCertificate(){
        certificate = Util.findFile(null, new File("."));
        if(certificate != null && certificate.exists()){
            certificateTextField.setText((certificate.getPath()));
        }
        else
            certificateTextField.setText("");
    }
    @FXML
    void loginButtonAction(ActionEvent event) {
        login();
    }

   private void login() {
        try (BufferedInputStream reader = new BufferedInputStream(new FileInputStream(users))) {
            MessageDigest m = MessageDigest.getInstance("SHA512");
            m.reset();
            String str =username.getText()+"::"+password.getText();
            byte[] c = m.digest(str.getBytes());
            boolean flag = false;
            byte[] b = null;
            while(!flag && (b = reader.readNBytes(64)).length != 0){
                if(Arrays.equals(c, b))
                    flag = true;
            }
            if(!flag)
                showMessage("Pogresano korisnicko ime ili lozinka");
            else if(certificate == null)
                showMessage("Sertifikat nije unesen");
            else{
                user = username.getText();
                FileInputStream in = new FileInputStream(certificate);
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
                in.close();
                if(!user.equals(cert.getSubjectDN().getName().split(",")[1].split("=")[1]))
                    showMessage("Selektovani sertifikat nije Vas");
                else {

                    ((Stage) username.getScene().getWindow()).close();
                    if (encryptRadioButton.isSelected()) {
                        Util.openWindow("src" + File.separator + "view" + File.separator + "Encrypt.fxml", 600, 500, true, false, new File("icons" + File.separator + "Icon.png"));
                    } else {
                        Util.openWindow("src" + File.separator + "view" + File.separator + "Decrypt.fxml", 600, 400, true, false, new File("icons" + File.separator + "Icon.png"));
                    }
                }
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        } catch (CertificateException e){
            showMessage("Niste selektovali sertifikat.");
            e.printStackTrace();
        }
    }

    public static void showMessage(String msg){
        MsgWindowController.setMessage(msg);
        Util.openWindow("src"+File.separator+"view"+File.separator+"MsgWindow.fxml",  535, 100, true, true, new File("icons"+File.separator+"Message.png"));
    }
}