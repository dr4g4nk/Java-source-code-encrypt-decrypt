package controllers;

import javafx.beans.property.Property;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import util.Util;
import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;

public class EncryptController {

    @FXML
    private TextField sourceFileTextField;

    @FXML
    private TextField privateKeyTextField;

    @FXML
    private ChoiceBox<String> encAlgChoiceBox;

    @FXML
    private ChoiceBox<String> hashAlgChoiceBox;

    @FXML
    private TextField rCertificateTextField;


    private File sourceFile;
    private File privateKey;
    private File rCertificate;


    @FXML
    private void initialize(){
        encAlgChoiceBox.getItems().addAll("AES", "DESEDE", "BLOWFISH");
        encAlgChoiceBox.getSelectionModel().selectFirst();
        hashAlgChoiceBox.getItems().addAll("SHA384", "SHA512");
        hashAlgChoiceBox.getSelectionModel().selectFirst();
    }

    @FXML
    void findSourceFileAction(ActionEvent event) {
        findSourceFile();
    }

    private void findSourceFile(){
        sourceFile = Util.findFile(new FileChooser.ExtensionFilter("Java source code", "*.java"), new File(System.getProperty("user.home")));
        if(sourceFile != null)
            sourceFileTextField.setText(sourceFile.getPath());
        else
            sourceFileTextField.setText("");
    }

    @FXML
    void findPrivateKeyAction(ActionEvent event) {
        findPrivateKey();
    }

    private void findPrivateKey(){
        privateKey = Util.findFile(null, new File("."+File.separator+"certificates"+File.separator+LoginController.getUser()));
        if(privateKey != null)
            privateKeyTextField.setText(privateKey.getPath());
        else
            privateKeyTextField.setText("");
    }

    @FXML
    void findRCertificateAction(ActionEvent event) {
        findRCertificate();
    }

    private void findRCertificate(){
        rCertificate = Util.findFile(null, new File("."+File.separator+"certificates"+File.separator+LoginController.getUser()+File.separator+"trustStore"));
        if(rCertificate != null)
            rCertificateTextField.setText(rCertificate.getPath());
    }

    @FXML
    void encryptButtonAction(ActionEvent event) {
        encrypt();
    }

    private void encrypt(){
        if((sourceFile != null && sourceFile.exists()) && (privateKey != null ) && (rCertificate != null && rCertificate.exists())) {
            try{
                X509Certificate cert = Util.checkCertificates(LoginController.getCertificate());
                X509Certificate rCert = Util.checkCertificates(rCertificate);

                PrivateKey key = Util.getPrivateKey(privateKey, cert.getPublicKey().getAlgorithm());
                if(key == null)
                    throw new Exception("Nije mogice procitati kljuc.");
                Cipher cipher = Cipher.getInstance(encAlgChoiceBox.getValue());
                KeyGenerator keyGenerator = KeyGenerator.getInstance(encAlgChoiceBox.getValue());
                byte alg = 0;
                if(encAlgChoiceBox.getValue().equals("AES")) {
                    keyGenerator.init(256);
                    alg |=16;
                }
                else if(encAlgChoiceBox.getValue().equals("BLOWFISH")) {
                    keyGenerator.init(448);
                    alg |= 32;
                }
                if(hashAlgChoiceBox.getValue().equals("SHA512"))
                    alg |= 8;

                Signature signature = Signature.getInstance(hashAlgChoiceBox.getValue()+"with"+cert.getPublicKey().getAlgorithm());
                signature.initSign(key);
                SecretKey secretKey = keyGenerator.generateKey();
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                FileInputStream reader = new FileInputStream(sourceFile);

                byte[] bytes = reader.readAllBytes();
                reader.close();
                signature.update(bytes);
                byte[] sign = signature.sign();
                byte[] keyByte = secretKey.getEncoded();
                byte[] tmp = new byte[keyByte.length+1];

                for(int i = 0; i<tmp.length; ++i){
                    if(i > 0)
                        tmp[i] = keyByte[i-1];
                    else
                        tmp[i] = alg;
                }

                FileOutputStream writer = new FileOutputStream(new File("ciphers" + File.separator + sourceFile.getName()));
                Cipher envelope = Cipher.getInstance(rCert.getPublicKey().getAlgorithm());
                envelope.init(Cipher.ENCRYPT_MODE, rCert.getPublicKey());
                byte[] env = envelope.doFinal(tmp);
                int n = env.length;
                writer.write(Integer.toString(n).getBytes().length);
                writer.write(Integer.toString(n).getBytes());
                writer.write(env);
                byte[] b = cipher.doFinal(LoginController.getUser().getBytes());
                writer.write(b.length);
                writer.write(b);
                writer.write(sign);
                writer.write(cipher.doFinal(bytes));
                writer.close();

                LoginController.showMessage("Enkripcija zavrsena");
            } catch(Exception e){
                LoginController.showMessage(e.getMessage());
                e.printStackTrace();
            }
        }
        else{
            if(sourceFile == null || !sourceFile.exists())
                LoginController.showMessage("Niste unijeli fajl ili ne postoji.");
            else if(rCertificate == null || !rCertificate.exists())
                LoginController.showMessage("Sertifikat primaoca nije unesen ili ne postoji.");
            else
                LoginController.showMessage("Niste selektovalil privatni kljuc.");
        }
    }

    @FXML
    void logoutButtonAction(ActionEvent event) {
        logout();
    }

    private void logout(){
        ((Stage)encAlgChoiceBox.getScene().getWindow()).close();
        Util.openWindow("src"+File.separator+"view" + File.separator + "Login.fxml", 630, 297, true, false, new File("icons"+File.separator+"Login.png"));
    }
}