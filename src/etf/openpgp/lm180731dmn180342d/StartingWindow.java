/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.lm180731dmn180342d;

import java.awt.event.ActionEvent;
import javax.swing.*;
import etf.openpgp.lm180731dmn180342d.ZPProjekat;

/**
 *
 * @author Nikola
 */
public class StartingWindow extends JFrame{
    
    private static StartingWindow instance = null;
    
    public static StartingWindow getInstance(){
        if(instance == null)
            instance = new StartingWindow();
        return instance;
    }
    
    public static void clearInstance(){
        instance = null;
    }
    
    private StartingWindow(){
        super(ZPProjekat.appName);
        this.setResizable(false);
        this.setSize(ZPProjekat.APP_WIDTH, ZPProjekat.APP_HEIGHT);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        
        JPanel panel = new JPanel();
        this.add(panel);
        
        panel.setLayout(null);
        
        
        
        JButton keysButton = new JButton("Keys");
        keysButton.setBounds(250, 200, 100, 25);
        keysButton.addActionListener((ActionEvent ae) -> {
            StartingWindow.getInstance().dispose();
            StartingWindow.clearInstance();
            KeysWindow.getInstance();
        });
        panel.add(keysButton);
       
        
        JButton encryptButton = new JButton("Encrypt");
        encryptButton.setBounds(370, 200, 100, 25);
        encryptButton.addActionListener((ActionEvent ae) -> {
            StartingWindow.getInstance().dispose();
            StartingWindow.clearInstance();
            EncryptWindow.getInstance();
        });
        panel.add(encryptButton);
        
        JButton decryptButton = new JButton("Decrypt");
        decryptButton.setBounds(490, 200, 100, 25);
        decryptButton.addActionListener((ActionEvent ae) -> {
            StartingWindow.getInstance().dispose();
            StartingWindow.clearInstance();
            DecryptWindow.getInstance();
        });
        panel.add(decryptButton);
        
        this.setVisible(true);
    }
}
