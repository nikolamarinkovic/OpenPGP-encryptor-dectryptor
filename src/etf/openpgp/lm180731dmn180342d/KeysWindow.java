/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.lm180731dmn180342d;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.math.BigInteger;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.plaf.multi.MultiLabelUI;
import javax.swing.table.DefaultTableModel;
import etf.openpgp.lm180731dmn180342d.Model;
import etf.openpgp.lm180731dmn180342d.ZPProjekat;

/**
 *
 * @author a-nikolam
 */
public class KeysWindow extends JFrame{
    
    private Model model = Model.getInstance();
    
    private static String status = "";
    
    private static KeysWindow instance = null;
    
    public static KeysWindow getInstance(){
        if(instance == null)
            instance = new KeysWindow();
        return instance;
    }
    
    public static void clearInstance(){
        instance = null;
    }
    
    private KeysWindow(){
        
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
            KeysWindow.getInstance().dispose();
            KeysWindow.clearInstance();
            StartingWindow.getInstance();
            status = "";
        });
        
        JLabel privateKeysLabel = new JLabel("Private keys:");
        privateKeysLabel.setBounds(20,40,100,25);
        panel.add(privateKeysLabel);
        
        JLabel publicKeysLabel = new JLabel("Public keys:");
        publicKeysLabel.setBounds(490,40,100,25);
        panel.add(publicKeysLabel);
        
        String privateColumnNames[] = {"UserID","Email","Primary key ID","Subkey ID"};
        
       
        List<Model.PrimaryKey> secretKeyRings = model.getSecretKeyRings();
        
        String privateKeyData[][] = new String[secretKeyRings.size()][4];
        
        for(int i = 0; i < secretKeyRings.size();i++){
            Model.PrimaryKey key = secretKeyRings.get(i);
            
            privateKeyData[i][0] = key.userId;
            privateKeyData[i][1] = key.email;
            privateKeyData[i][2] = Long.toHexString(key.keyId);
            
            Model.Subkey subkey = key.subkey;
            if(subkey != null){
                 privateKeyData[i][3] = Long.toHexString(subkey.keyId);
            }
            else{
                privateKeyData[i][3] = "";
            }
           
            
        }

        //String privateKeyData[][] = {{"123","Mrci","mrci@gm.com"},{"124","Foxy","Foxy@gm.com"}};
        
        JTable privateKeyTable = new JTable(privateKeyData,privateColumnNames){
            @Override
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
        };
        privateKeyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        privateKeyTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        privateKeyTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        privateKeyTable.getColumnModel().getColumn(2).setPreferredWidth(140);
        
        JScrollPane privateScrollPane = new JScrollPane(privateKeyTable);
        privateScrollPane.setSize(430,200);
        privateScrollPane.setBounds(20,70,430,200);
        panel.add(privateScrollPane);
        
        String publicColumnNames[] = {"UserID","Email","Primary key ID","Subkey ID"};
        List<Model.PrimaryKey> publicKeyRings = model.getPublicKeyRings();
        publicKeyRings.addAll(model.getSecretKeyRings());
        
        String publicKeyData[][] = new String[publicKeyRings.size()][4];
        
        for(int i = 0; i < publicKeyRings.size();i++){
            Model.PrimaryKey key = publicKeyRings.get(i);
            
            publicKeyData[i][0] = key.userId;
            publicKeyData[i][1] = key.email;
            publicKeyData[i][2] = Long.toHexString(key.keyId);
            
            Model.Subkey subkey = key.subkey;
            if(subkey != null){
                 publicKeyData[i][3] = Long.toHexString(subkey.keyId);
            }
            else{
                publicKeyData[i][3] = "";
            }
           
            
        }
        
        //String publicColumnNames[] = {"Id","Name","Email"};
        //String publicKeyData[][] = {{"1234","Mrci1","mrci1@gm.com"},{"1245","Foxy2","Foxy2@gm.com"}};
        
        JTable publicKeyTable = new JTable(publicKeyData,publicColumnNames){
            @Override
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
        };
        publicKeyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        publicKeyTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        publicKeyTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        publicKeyTable.getColumnModel().getColumn(2).setPreferredWidth(140);
        
        JScrollPane publicScrollPane = new JScrollPane(publicKeyTable);
        publicScrollPane.setSize(430,200);
        publicScrollPane.setBounds(480,70,430,200);
        panel.add(publicScrollPane);
        
        JLabel errorLabel = new JLabel("");
        errorLabel.setBounds(280,380,350,200);
        panel.add(errorLabel);
        
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(150,330,100,25);
        panel.add(passwordLabel);
        
        JTextField passwordTextField = new JTextField(50);
        passwordTextField.setBounds(220,330,200,25);
        panel.add(passwordTextField);
        
        
        JButton importPrivateKeyButton = new JButton("Import private key");
        importPrivateKeyButton.setBounds(20, 300, 140, 25);
        panel.add(importPrivateKeyButton);
        importPrivateKeyButton.addActionListener((ActionEvent ae) -> {
            JFileChooser fileChooser = new JFileChooser();
            int retVal = fileChooser.showOpenDialog(KeysWindow.this);
            if(retVal == JFileChooser.APPROVE_OPTION){
                String filename = fileChooser.getSelectedFile().getAbsolutePath();
                status = "<html>" + model.importSecretKeys(filename) + "</html>" ;
                refreshPage();
            }
        });
        
        JButton exportPrivateKeyButton = new JButton("Export private key");
        exportPrivateKeyButton.setBounds(170, 300, 140, 25);
        panel.add(exportPrivateKeyButton);
        exportPrivateKeyButton.addActionListener((ActionEvent ae) -> {
            
            int selectedRow = privateKeyTable.getSelectedRow();
            if(selectedRow == -1){
                errorLabel.setText("Select row to export key.");
                return;
            }
            
            JFileChooser fileChooser = new JFileChooser();
            int retVal = fileChooser.showSaveDialog(KeysWindow.this);
            if(retVal == JFileChooser.APPROVE_OPTION){
                
                BigInteger tmp = new BigInteger(privateKeyData[selectedRow][2], 16);
                Long primaryKeyId = tmp.longValue();
                String filename = fileChooser.getSelectedFile().getAbsolutePath();
                status = "<html>" + model.exportSecretKey(primaryKeyId, filename) + "</html>";
                refreshPage();
                        
            }
        });
        
        JButton deletePrivateKeyButton = new JButton("Delete private key");
        deletePrivateKeyButton.setBounds(320, 300, 140, 25);
        panel.add(deletePrivateKeyButton);
        deletePrivateKeyButton.addActionListener((ActionEvent ae) -> {
            int selectedRow = privateKeyTable.getSelectedRow();
            if(selectedRow == -1){
                errorLabel.setText("Select row to delete.");
                return;
            }
            
            String password = passwordTextField.getText();
            
            BigInteger tmp = new BigInteger(privateKeyData[selectedRow][2], 16);
            Long primaryKeyId = tmp.longValue();
            
            status = "<html>" + model.deleteSecretKeyPair(primaryKeyId, password) + "</html>";
            refreshPage();
            
        });
        
        JButton importPublicKeyButton = new JButton("Import public key");
        importPublicKeyButton.setBounds(470, 300, 140, 25);
        panel.add(importPublicKeyButton);
        importPublicKeyButton.addActionListener((ActionEvent ae) -> {
            JFileChooser fileChooser = new JFileChooser();
            int retVal = fileChooser.showOpenDialog(KeysWindow.this);
            if(retVal == JFileChooser.APPROVE_OPTION){
                
               String filename = fileChooser.getSelectedFile().getAbsolutePath();
               status = "<html>" + model.importPublicKeys(filename) + "</html>";
               refreshPage();
                
            }
            
        });
        
        JButton exportPublicKeyButton = new JButton("Export public key");
        exportPublicKeyButton.setBounds(620, 300, 140, 25);
        panel.add(exportPublicKeyButton);
        exportPublicKeyButton.addActionListener((ActionEvent ae) -> {
            
            int selectedRow = publicKeyTable.getSelectedRow();
            if(selectedRow == -1){
                errorLabel.setText("Select row to export key.");
                return;
            }
            
            JFileChooser fileChooser = new JFileChooser();
            int retVal = fileChooser.showSaveDialog(KeysWindow.this);
            if(retVal == JFileChooser.APPROVE_OPTION){
                BigInteger tmp = new BigInteger(publicKeyData[selectedRow][2], 16);
                Long primaryKeyId = tmp.longValue();
                String filename = fileChooser.getSelectedFile().getAbsolutePath();
                status = "<html>" + model.exportPublicKey(primaryKeyId, filename) + "</html>";
                refreshPage();
            }
            
        });
        
        JButton deletePublicKeyButton = new JButton("Delete public key");
        deletePublicKeyButton.setBounds(770, 300, 140, 25);
        panel.add(deletePublicKeyButton);
        deletePublicKeyButton.addActionListener((ActionEvent ae) -> {
            int selectedRow = publicKeyTable.getSelectedRow();
            if(selectedRow == -1){
                errorLabel.setText("Select row to delete.");
                return;
            }
            
            BigInteger tmp = new BigInteger(publicKeyData[selectedRow][2], 16);
            Long primaryKeyId = tmp.longValue();
            
            status = "<html>" + model.deletePublicKeyPair(primaryKeyId) + "</html>";
            refreshPage();
            
            
        });
        
        JButton newKeyButton = new JButton("New key");
        newKeyButton.setBounds(370, 360, 150, 25);
        panel.add(newKeyButton);
        newKeyButton.addActionListener((ActionEvent ae) -> {
            KeysWindow.getInstance().dispose();
            KeysWindow.clearInstance();
            NewKeyWindow.getInstance();
        });

        

        this.setVisible(true);
        
    }
    
    public void refreshPage(){
        KeysWindow.getInstance().dispose();
        KeysWindow.clearInstance();
        KeysWindow.getInstance();
    }
}
