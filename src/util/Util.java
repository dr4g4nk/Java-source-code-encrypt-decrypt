package util;

import controllers.LoginController;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Util {

    public static void openWindow(String path, double width, double height, boolean disableResizable, boolean msgWindow, File image) {
        try {
            Parent root = FXMLLoader.load(new File(path).toURI().toURL());
            Stage stage = new Stage();
            stage.setScene(new Scene(root, width, height));
            stage.setMinWidth(width);
            stage.setMinHeight(height);
            stage.getIcons().add(new Image(new FileInputStream(image)));
            if(disableResizable) {
                stage.setMaxWidth(width);
                stage.setMaxHeight(height);
                stage.setMinWidth(width);
                stage.setMinHeight(height);
                stage.setResizable(false);
            }
            if(msgWindow)
                stage.showAndWait();
            else
                stage.show();
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public static File findFile(FileChooser.ExtensionFilter filter, File dir){
        FileChooser chooser = new FileChooser();
        if(filter != null)
            chooser.getExtensionFilters().add(filter);
        if(dir != null)
            chooser.setInitialDirectory(dir);
        return chooser.showOpenDialog(null);
    }

    public static PrivateKey getPrivateKey(File privateKeyFile, String algorithm){
        PrivateKey key = null;
        try {
            PemReader pemReader = new PemReader(new FileReader(privateKeyFile));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());

            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            key = keyFactory.generatePrivate(keySpec);
        } catch(NoSuchAlgorithmException | InvalidKeySpecException | IOException e){
            e.printStackTrace();
        }
        return key;
    }

    public static X509Certificate checkCertificates(File certFile) throws Exception{
        try (FileInputStream certFileInputStream = new FileInputStream(certFile);
             FileInputStream rootFile = new FileInputStream(new File("certificates" + File.separator + "root" + File.separator + "root.crt"));
             FileInputStream crlFile = new FileInputStream(new File("certificates" + File.separator + "root" + File.separator + "list.crl"))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate root = (X509Certificate) factory.generateCertificate(rootFile);
            X509CRL crl = (X509CRL) factory.generateCRL(crlFile);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(certFileInputStream);
            if (crl.isRevoked(cert))
                throw new CertificateIsRevokedException();

            cert.verify(root.getPublicKey());
            cert.checkValidity();

            return cert;

        }catch (CertificateNotYetValidException |NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | CertificateExpiredException | SignatureException e) {
            throw new Exception("Jedan od sertifikata nije validan");
        } catch(CRLException | CertificateException | IOException e) {
            e.printStackTrace();
            throw new Exception("Jedan od fajlova ne postoji(sertifikati ili crl lista)");
        } catch (CertificateIsRevokedException e){
            e.printStackTrace();
            throw new Exception("Jedan od sertifikata je povucen");
        }
    }
}