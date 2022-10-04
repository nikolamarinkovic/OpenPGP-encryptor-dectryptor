/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package etf.openpgp.lm180731dmn180342d;

import java.awt.Color;
import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import etf.openpgp.lm180731dmn180342d.Model;
import etf.openpgp.lm180731dmn180342d.ZPProjekat;

/**
 *
 * @author a-nikolam
 */
public class NewKeyWindow extends JFrame{
    
    private Model model = Model.getInstance();
    
    private static NewKeyWindow instance = null;
    
    public static NewKeyWindow getInstance(){
        if(instance == null)
            instance = new NewKeyWindow();
        return instance;
    }
    
    public static void clearInstance(){
        instance = null;
    }
    
    private NewKeyWindow(){
        
        super(ZPProjekat.appName);
        this.setResizable(false);
        this.setSize(ZPProjekat.APP_WIDTH, ZPProjekat.APP_HEIGHT);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel panel = new JPanel();
        this.add(panel);
        
        panel.setLayout(null);
        
        JButton keysButton = new JButton("Back");
        keysButton.setBounds(0, 0, 80, 25);
        panel.add(keysButton);
        keysButton.addActionListener((ActionEvent ae) -> {
            NewKeyWindow.getInstance().dispose();
            NewKeyWindow.clearInstance();
            KeysWindow.getInstance();
        });
        
        JLabel emailLabel = new JLabel("Email:");
        emailLabel.setBounds(10,50,80,25);
        panel.add(emailLabel);
        
        JTextField emailTextField = new JTextField(50);
        emailTextField.setBounds(100,50,300,25);
        panel.add(emailTextField);
        
        JLabel nameLabel = new JLabel("Name:");
        nameLabel.setBounds(10,80,80,25);
        panel.add(nameLabel);
        
        JTextField nameTextField = new JTextField(50);
        nameTextField.setBounds(100,80,300,25);
        panel.add(nameTextField);
        
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(10,110,80,25);
        panel.add(passwordLabel);
        
        JPasswordField passwordTextField = new JPasswordField(50);
        passwordTextField.setBounds(100,110,300,25);
        panel.add(passwordTextField);
        
        JLabel asymemetricKeyLabel = new JLabel("Asymemetric key:");
        asymemetricKeyLabel.setBounds(60,150,110,25);
        panel.add(asymemetricKeyLabel);
        
        String[] asymetricKeyAlgorithms = {"DSA-1024 bit key", "DSA-2048 bit key"};
        JComboBox<String> jComboBox = new JComboBox<>(asymetricKeyAlgorithms);
        jComboBox.setBounds(180,150,110,25);
        panel.add(jComboBox);
        
        JButton generateKeyButton = new JButton("Generate key");
        generateKeyButton.setBounds(160, 200, 150, 25);
        panel.add(generateKeyButton);
        generateKeyButton.addActionListener((ActionEvent ae) -> {
            
            String userID = nameTextField.getText() + "<" + emailTextField.getText() + ">";
            
            int DSALen[] = {1024,2048};
            int ELGamalLen[] = {1024,2048, 4096};
            
            model.generateKeyPairs(userID, passwordTextField.getText(), DSALen[jComboBox.getSelectedIndex()], 1024);
            
        });
        
        JLabel errorLabel = new JLabel("Error");
        errorLabel.setBounds(220,230,200,25);
        errorLabel.setForeground(Color.red);
        panel.add(errorLabel);
        
        
        this.setVisible(true);
        
    }
    
}
