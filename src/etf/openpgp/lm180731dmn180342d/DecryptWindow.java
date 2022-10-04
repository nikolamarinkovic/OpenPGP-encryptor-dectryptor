/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.lm180731dmn180342d;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import etf.openpgp.lm180731dmn180342d.Model;
import etf.openpgp.lm180731dmn180342d.ZPProjekat;

/**
 *
 * @author a-nikolam
 */
public class DecryptWindow extends JFrame {
    
    private static DecryptWindow instance = null;
    
    public static DecryptWindow getInstance(){
        if(instance == null)
            instance = new DecryptWindow();
        return instance;
    }
    
    public static void clearInstance(){
        instance = null;
    }
    
    private Model model = Model.getInstance();
    
    public DecryptWindow(){
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
            DecryptWindow.getInstance().dispose();
            DecryptWindow.clearInstance();
            StartingWindow.getInstance();
        });
        
        JLabel errorLabel = new JLabel("wdawdawdawdaw");
        errorLabel.setBounds(370,280,500,120);
        panel.add(errorLabel);
        
        JLabel inputFileLocationLabel = new JLabel("File source:");
        inputFileLocationLabel.setBounds(10,30,90,30);
        panel.add(inputFileLocationLabel);
        
        JTextField inputFileLocationTextField = new JTextField(256);
        inputFileLocationTextField.setBounds(80,30,300,30);
        inputFileLocationTextField.setEditable(false);
        panel.add(inputFileLocationTextField);
        
        JLabel privateKeyLabel =  new JLabel("Private key:");
        privateKeyLabel.setBounds(10,90,80,20);
        panel.add(privateKeyLabel);
        
        String[] privateKeys = {};
        JComboBox<String> comboBoxPrivateKeys = new JComboBox<>(privateKeys);
        comboBoxPrivateKeys.setBounds(85,90,300,30);
        comboBoxPrivateKeys.setEnabled(false);
        panel.add(comboBoxPrivateKeys);
        
        JLabel passwordLabel =  new JLabel("Password:");
        passwordLabel.setBounds(410,90,70,20);
        panel.add(passwordLabel);
        
        JTextField passwordTextField = new JTextField(50);
        passwordTextField.setEditable(false);
        passwordTextField.setBounds(480, 90, 300, 30);
        panel.add(passwordTextField);
        
        JButton selectInputFileButton = new JButton("Select file");
        selectInputFileButton.setBounds(400,30,100,30);
        selectInputFileButton.addActionListener((ActionEvent e) -> {
             JFileChooser fileChooser = new JFileChooser();
             int retVal = fileChooser.showOpenDialog(DecryptWindow.this);
             if(retVal == JFileChooser.APPROVE_OPTION){
                 passwordTextField.setEditable(false);
                 comboBoxPrivateKeys.setEnabled(false);
                 inputFileLocationTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                 //enable polje za lozinku
                 List<Model.PrimaryKey> findKeyId = model.findKeyId(inputFileLocationTextField.getText());
                 if(findKeyId == null){
                     errorLabel.setText("Exception occured.");
                     return;
                 }
                 
                 passwordTextField.setEditable(true);
                 comboBoxPrivateKeys.setEnabled(true);
                 
                 for(int i = 0; i < findKeyId.size(); i++){
                     Model.PrimaryKey item = findKeyId.get(i);
                     comboBoxPrivateKeys.addItem(item.userId + "," + item.email + "," + Long.toHexString(item.subkey.keyId));
                 }
             }
             
        });
        panel.add(selectInputFileButton);

        JLabel outputFileLocationLabel = new JLabel("File destination:");
        outputFileLocationLabel.setBounds(10,160,90,30);
        panel.add(outputFileLocationLabel);
        
        JTextField outputFileLocationTextField = new JTextField(256);
        outputFileLocationTextField.setBounds(105,160,300,30);
        outputFileLocationTextField.setEditable(false);
        panel.add(outputFileLocationTextField);
       
        JButton selectOutputFileButton = new JButton("Select file");
        selectOutputFileButton.setBounds(420,160,100,30);
        selectOutputFileButton.addActionListener((ActionEvent e) -> {
             JFileChooser fileChooser = new JFileChooser();
             int retVal = fileChooser.showSaveDialog(DecryptWindow.this);
             if(retVal == JFileChooser.APPROVE_OPTION){
                 outputFileLocationTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
                 List<Model.PrimaryKey> findKeyId = model.findKeyId(outputFileLocationTextField.getText());
                 
             }
             
        });
        panel.add(selectOutputFileButton);
        
        
        
        
        JButton decryptButton = new JButton("Decrypt");
        decryptButton.setBounds(350, 280, 80, 25);
        panel.add(decryptButton);
        decryptButton.addActionListener((ActionEvent ae) -> {
            String selectedPK = (String) comboBoxPrivateKeys.getSelectedItem();
            if(selectedPK == null){
                errorLabel.setText("<html>" + model.receiveMessage(inputFileLocationTextField.getText(), outputFileLocationTextField.getText(), null, null) + "</html>");
                return;
            }
            String[] splittedPK = selectedPK.split(",");
            BigInteger tmp2 = new BigInteger(splittedPK[2], 16); 
            
            errorLabel.setText("<html>" + model.receiveMessage(inputFileLocationTextField.getText(), outputFileLocationTextField.getText(), tmp2.longValue(), passwordTextField.getText() + "</html>"));
            return;
        });
        
        this.setVisible(true);
        
    }
}
