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
import java.util.ArrayList;
import java.util.List;
import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import etf.openpgp.lm180731dmn180342d.Model;
import etf.openpgp.lm180731dmn180342d.ZPProjekat;

/**
 *
 * @author a-nikolam
 */
public class EncryptWindow extends JFrame{
    
    private static EncryptWindow instance = null;
    
    public static EncryptWindow getInstance(){
        if(instance == null)
            instance = new EncryptWindow();
        return instance;
    }
    
    public static void clearInstance(){
        instance = null;
    }
    
    private Model model = Model.getInstance();
    
    public EncryptWindow(){
        
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
            EncryptWindow.getInstance().dispose();
            EncryptWindow.clearInstance();
            StartingWindow.getInstance();
        });
        
        JLabel privateKeyLabel =  new JLabel("Private key:");
        privateKeyLabel.setBounds(0,30,100,20);
        panel.add(privateKeyLabel);
        
        
        
        
        List<Model.PrimaryKey> secretKeyRings = model.getSecretKeyRings();
        String[] privateKeys = new String[secretKeyRings.size()];
        for(int i = 0; i < secretKeyRings.size(); i++){
            Model.PrimaryKey ring = secretKeyRings.get(i);
            privateKeys[i] = ring.userId + "," + ring.email + "," + Long.toHexString(ring.keyId);;
        }
        
        
        JComboBox<String> comboBoxPrivateKeys = new JComboBox<>(privateKeys);
        comboBoxPrivateKeys.setBounds(70,30,100,20);
        comboBoxPrivateKeys.setEnabled(false);
        panel.add(comboBoxPrivateKeys);

        JLabel publicKeyLabel =  new JLabel("Public key:");
        publicKeyLabel.setBounds(180,30,100,20);
        panel.add(publicKeyLabel);
        
        List<Model.PrimaryKey> publicKeyRings = model.getPublicKeyRings();
        publicKeyRings.addAll(model.getSecretKeyRings());
        int n = 0;
        
        for(int i = 0; i < publicKeyRings.size(); i++){
            Model.PrimaryKey ring = publicKeyRings.get(i);
            if(ring.subkey != null)
                n++;
        }
        
        int j = 0;
        
        String[] publicKeys = new String[n];
        for(int i = 0; i < publicKeyRings.size(); i++){
            Model.PrimaryKey ring = publicKeyRings.get(i);
            if(ring.subkey != null){
                publicKeys[j++] = ring.userId + "," + ring.email + "," +  Long.toHexString(ring.subkey.keyId);
                if(j == n)
                    break; //efficenci
            }
            
        }
        //JComboBox<String> comboBoxPublicKeys = new JComboBox<>(publicKeys);
        //comboBoxPublicKeys.setBounds(245,30,110,20);
        //comboBoxPublicKeys.setEnabled(false);
        
        JList<String> listPublicKeys = new JList<String>(publicKeys);
        listPublicKeys.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        listPublicKeys.setEnabled(false);
        
        JScrollPane jcp = new JScrollPane(listPublicKeys);
        //jcp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jcp.setBounds(245,30,350,40);
        panel.add(jcp);
       
        
        JLabel cryptographyAlgorithmLabel =  new JLabel("Cryptography algorithm:");
        cryptographyAlgorithmLabel.setBounds(610,30,150,20);
        panel.add(cryptographyAlgorithmLabel);
        
        String[] symmetricAlgorithms = {"3DES with EDE configuration", "AES 128 bit key"};
        JComboBox<String> comboBoxSymmetricAlgorithms = new JComboBox<>(symmetricAlgorithms);
        comboBoxSymmetricAlgorithms.setBounds(750,30,170,20);
        comboBoxSymmetricAlgorithms.setEnabled(false);
        panel.add(comboBoxSymmetricAlgorithms);
        
        JLabel plainTextLabel =  new JLabel("Message source file:");
        plainTextLabel.setBounds(10,80,120,25);
        panel.add(plainTextLabel);
        
        JTextField inputFileLocationTextField = new JTextField(256);
        inputFileLocationTextField.setBounds(135,80,300,30);
        inputFileLocationTextField.setEditable(false);
        panel.add(inputFileLocationTextField);
        
        JButton selectInputFileButton = new JButton("Select file");
        selectInputFileButton.setBounds(450,80,100,30);
        selectInputFileButton.addActionListener((ActionEvent e) -> {
             JFileChooser fileChooser = new JFileChooser();
             int retVal = fileChooser.showOpenDialog(EncryptWindow.this);
             if(retVal == JFileChooser.APPROVE_OPTION){
                 inputFileLocationTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
             }

        });
        panel.add(selectInputFileButton);

        
        JCheckBox encryptBox = new JCheckBox("Encrypt");
        encryptBox.setBounds(50,180,70,25);
        encryptBox.addActionListener((ActionEvent ae) -> {
            AbstractButton abstractButton = (AbstractButton) ae.getSource();
            boolean selected = abstractButton.getModel().isSelected();
            listPublicKeys.setEnabled(selected);
            comboBoxSymmetricAlgorithms.setEnabled(selected);
        });
        panel.add(encryptBox);
        
        JLabel signaturePasswordLabel = new JLabel("Private key password:");
        signaturePasswordLabel.setBounds(30,140,140,25);
        panel.add(signaturePasswordLabel);
        
        JPasswordField passwordTextField = new JPasswordField(50);
        passwordTextField.setEditable(false);
        passwordTextField.setBounds(160,140,200,25);
        panel.add(passwordTextField);
        
        JCheckBox signBox = new JCheckBox("Sign");
        signBox.setBounds(130,180,50,25);
        signBox.addActionListener((ActionEvent ae) -> {
            AbstractButton abstractButton = (AbstractButton) ae.getSource();
            boolean selected = abstractButton.getModel().isSelected();
            comboBoxPrivateKeys.setEnabled(selected);
            passwordTextField.setEditable(selected);
            
        });
        panel.add(signBox);
        
        JCheckBox compressBox = new JCheckBox("Compress");
        compressBox.setBounds(190,180,100,25);
        panel.add(compressBox);
        
        JCheckBox radixBox = new JCheckBox("Radix");
        radixBox.setBounds(290,180,70,25);
        panel.add(radixBox);
        
        JLabel fileLocationLabel = new JLabel("File destination:");
        fileLocationLabel.setBounds(10,230,90,30);
        panel.add(fileLocationLabel);
        
        JTextField outputFileLocationTextField = new JTextField(256);
        outputFileLocationTextField.setBounds(100,230,300,30);
        outputFileLocationTextField.setEditable(false);
        panel.add(outputFileLocationTextField);
        
        JButton selectOutputFileButton = new JButton("Select file");
        selectOutputFileButton.setBounds(410,230,100,30);
        selectOutputFileButton.addActionListener((ActionEvent e) -> {
             JFileChooser fileChooser = new JFileChooser();
             int retVal = fileChooser.showSaveDialog(EncryptWindow.this);
             if(retVal == JFileChooser.APPROVE_OPTION){
                 outputFileLocationTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
             }
             
        });
        panel.add(selectOutputFileButton);
        
        JLabel errorLabel = new JLabel("wdawdawwdasdasd"); // this must go before button, to change the content later
        errorLabel.setBounds(225,300,500,120);
        panel.add(errorLabel);
        
        JButton encryptButton = new JButton("Encrypt");
        encryptButton.setBounds(200, 275, 80, 25);
        panel.add(encryptButton);
        encryptButton.addActionListener((ActionEvent ae) -> {
            String cryptingAlgorithm = null;
            String privateKey = null;
            String dstFile = outputFileLocationTextField.getText();
            String srcFile = inputFileLocationTextField.getText();
            boolean compress = compressBox.isSelected();
            boolean radix64 = radixBox.isSelected();
            Long secretKeyID = null;
            String password = null;
            List<Long> publicKeyIDList = new ArrayList<Long>();
            
            if(encryptBox.isSelected()){

                int cryptographyIndex = comboBoxSymmetricAlgorithms.getSelectedIndex();
                if(cryptographyIndex == 0)
                    cryptingAlgorithm = "3DES";
                else if(cryptographyIndex == 1)
                    cryptingAlgorithm = "AES128";
                
                List<String> selectedPublicKeys = listPublicKeys.getSelectedValuesList();
                
                for(int i = 0; i < selectedPublicKeys.size(); i++){
                    String selectedItem = selectedPublicKeys.get(i);
                    String[] split = selectedItem.split(",");
                    String id = split[2];
                    
                    BigInteger tmp2 = new BigInteger(id, 16); 
                    publicKeyIDList.add(tmp2.longValue());
                }
                
                password = passwordTextField.getText();
                
            }
            if(signBox.isSelected()){
                //privateKey = 
                String selectedItem = (String) comboBoxPrivateKeys.getSelectedItem();
                String[] split = selectedItem.split(",");
                String id = split[2];
                
                BigInteger tmp = new BigInteger(id, 16);
                secretKeyID = tmp.longValue();
                
                password = passwordTextField.getText();
            }
            
            errorLabel.setText("<html>" + model.sendMessage(dstFile, srcFile, cryptingAlgorithm, compress, radix64, secretKeyID, password, publicKeyIDList) + "</html>");
        });
        
        
        this.setVisible(true);
    }
    
}
