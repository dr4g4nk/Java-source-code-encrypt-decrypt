import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import java.io.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Main extends Application {

    @Override
    public void start(Stage primaryStage) {
        try {
            Parent root = FXMLLoader.load(new File("src"+File.separator+"view" + File.separator + "Login.fxml").toURI().toURL());
            primaryStage.setTitle("Login");
            primaryStage.setScene(new Scene(root, 630, 297));
            primaryStage.setMaxWidth(630);
            primaryStage.setMinWidth(630);
            primaryStage.setMinHeight(297);
            primaryStage.setMaxHeight(297);
            primaryStage.setResizable(false);
            primaryStage.getIcons().add(new Image(new FileInputStream("icons"+File.separator+"Login.png")));
            primaryStage.show();
        } catch(IOException e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        launch(args);
    }
}