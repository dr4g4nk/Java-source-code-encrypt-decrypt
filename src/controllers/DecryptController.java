package controllers;

import com.sun.javafx.iio.ImageFormatDescription;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.util.Pair;
import util.Util;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.stream.Stream;

public class DecryptController {

    @FXML
    private TextField fileTextField;

    @FXML
    private TextField privateKeyTextField;

    private File file;
    private File privateKeyFile;

    @FXML
    void findFileAction(ActionEvent event) {
        findFile();
    }

    private void findFile(){
        file = Util.findFile(null, new File(System.getProperty("user.home")));
        if(file != null)
            fileTextField.setText(file.getPath());
        else
            fileTextField.setText("");
    }

    @FXML
    void findPrivateKeyAction(ActionEvent event) {
        findPrivateKey();
    }

    private void findPrivateKey(){
        privateKeyFile = Util.findFile(null, new File("."+File.separator+"certificates"+File.separator+LoginController.getUser()));
        if(privateKeyFile != null)
            privateKeyTextField.setText(privateKeyFile.getPath());
        else
            privateKeyTextField.setText("");
    }

    @FXML
    void decryptButtonAction(ActionEvent event) {
        decrypt();
    }

    private void decrypt(){
        if(file != null && file.exists() && privateKeyFile != null && privateKeyFile.exists()) {
            try (FileInputStream reader = new FileInputStream(file)) {

                X509Certificate cert = Util.checkCertificates(LoginController.getCertificate());
                PrivateKey privateKey = Util.getPrivateKey(privateKeyFile, cert.getPublicKey().getAlgorithm());

                if(privateKey == null)
                    throw new Exception("Nije moguce procitati kljuc");
                Cipher cipher = Cipher.getInstance(cert.getPublicKey().getAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, privateKey);

                int tmp = reader.read();
                int p = Integer.parseInt(new String(reader.readNBytes(tmp)));
                byte[] alg = cipher.doFinal(reader.readNBytes(p));
                String algorithm = "DESEDE";
                String hash = "SHA384";
                if(alg[0] == 8)
                    hash = "SHA512";
                else if(alg[0] == 16 || alg[0] == 24) {
                    algorithm = "AES";
                    if(alg[0] == 24)
                        hash = "SHA512";
                }
                else if(alg[0] == 32 || alg[0] == 40){
                    algorithm = "BLOWFISH";
                    if(alg[0] == 40)
                        hash = "SHA512";
                }
                byte[] key = Arrays.copyOfRange(alg, 1, alg.length);
                SecretKey secretKey = new SecretKeySpec(key, algorithm);
                Cipher simCipher = Cipher.getInstance(algorithm);
                simCipher.init(Cipher.DECRYPT_MODE, secretKey);
                int len = reader.read();
                byte[] user = simCipher.doFinal(reader.readNBytes(len));
                File[] files = Arrays.stream(new File("."+File.separator+"certificates"+File.separator+LoginController.getUser()+File.separator+"trustStore").listFiles()).filter(e -> e.getName().endsWith(".cer") || e.getName().endsWith(".crt") || e.getName().endsWith(".pem") || e.getName().endsWith(".der")).toArray(File[]::new);
                X509Certificate otherCert = null;
                boolean flag = true;
                int n = -1;
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                for(int i=0; flag && i<files.length; ++i) {
                    try (FileInputStream in = new FileInputStream(files[i])) {
                        otherCert = (X509Certificate) factory.generateCertificate(in);
                        if (Arrays.equals(user, otherCert.getSubjectDN().getName().split(",")[1].split("=")[1].getBytes())){
                            flag = false;
                            n = i;
                        }
                    } catch (CertificateException e) {
                        e.printStackTrace();
                    }
                }

                Util.checkCertificates(files[n]);

                if(otherCert != null)
                {
                    byte[] sign = reader.readNBytes(p);
                    byte[] bytes = simCipher.doFinal(reader.readAllBytes());
                    Signature signature = Signature.getInstance(hash+"with"+otherCert.getPublicKey().getAlgorithm());
                    signature.initVerify(otherCert);
                    signature.update(bytes);
                    if(!signature.verify(sign))
                        throw new SignatureException();

                    File sourceFile;
                    FileOutputStream source = new FileOutputStream((sourceFile = new File(file.getName())));
                    source.write(bytes);
                    source.close();
                    SourceCodeController.setFile(sourceFile);
                    SourceCodeController.setText(bytes);
                    Util.openWindow("src"+File.separator+"view"+File.separator+"SourceCode.fxml",  716, 769, false, false, new File("icons"+File.separator+"Icon.png"));
                }
                else{
                    LoginController.showMessage("Ne postoji sertifikat za korisnika koji je kriptovao datoteku");
                }
            } catch (SignatureException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                LoginController.showMessage("Datoteka je kompromitovana");
                e.printStackTrace();
            } catch (IOException | CertificateException e){
                LoginController.showMessage("Nema sertifikata");
                e.printStackTrace();
            } catch(Exception e){
                LoginController.showMessage(e.getMessage());
                e.printStackTrace();
            }
        }
        else{
            if(file == null || !file.exists())
                LoginController.showMessage("Niste selektovali fajl ili ne postoji");
            else
                LoginController.showMessage("Niste selektovali privatni kljuc.");
        }
    }

    @FXML
    void logoutButtonAction(ActionEvent event) {
        logout();
    }

    private void logout(){
        ((Stage)fileTextField.getScene().getWindow()).close();
        Util.openWindow("src"+File.separator+"view" + File.separator + "Login.fxml", 630, 297, true, false, new File("icons"+File.separator+"Login.png"));
    }
}