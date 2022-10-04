/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.lm180731dmn180342d;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 *
 * @author Fox
 */
public class MainConsole {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Model model = new Model();

        while (true) {
            String command = scanner.nextLine();

            if (command.indexOf("help") == 0) {
                System.out.println("generate key pair <username> <passphrase> <DSA key size> {<El Gamal key size>}");
                System.out.println("list secret keys");
                System.out.println("list public keys");
                System.out.println("send message <input file name> <output file name> <compression enabled>  <radix enabled> <secret key id> <passphrase> <coma separated public key ids>");
                System.out.println("receive message <input file name> <output file name> <passphrase>");
                System.out.println("import secret key <input file name>");
                System.out.println("import public key <input file name>");
                System.out.println("export secret key <key id> <output file name>");
                System.out.println("export public key <key id> <output file name>");
                System.out.println("delete secret key <key id>  <passphrase>");
                System.out.println("delete public key <key id>");
                System.out.println("help");
            } else if (command.indexOf("generate key pair") == 0) {
                String[] arguments = command.substring("generate key pair".length() + 1).split(" ");
                if (arguments.length < 3) {
                    System.out.println("Invalid arguments");
                    continue;
                }
                String username = arguments[0];
                String passphrase = arguments[1];
                Integer DSAKeySize = null;
                try {
                    DSAKeySize = Integer.parseInt(arguments[2]);
                } catch (NumberFormatException nfe) {
                    System.out.println("Invalid key size");
                    continue;
                }
                Integer ElGamalKeySize = null;
                try {
                    ElGamalKeySize = Integer.parseInt(arguments[3]);
                } catch (NumberFormatException nfe) {
                    System.out.println("Invalid key size");
                    continue;
                } catch (IndexOutOfBoundsException ioobe) {
                }

                model.generateKeyPairs(username, passphrase, DSAKeySize, DSAKeySize);

            } else if (command.indexOf("list secret keys") == 0) {
                List<Model.PrimaryKey> secretKeyRings = model.getSecretKeyRings();
                for (Model.PrimaryKey primaryKey : secretKeyRings) {
                    System.out.println(primaryKey.userId + " " + primaryKey.email + " " + Long.toHexString(primaryKey.keyId));
                    if (primaryKey.subkey != null) {
                        System.out.println("\t" + Long.toHexString(primaryKey.subkey.keyId));
                    }
                }

            } else if (command.indexOf("list public keys") == 0) {
                List<Model.PrimaryKey> publicKeyRings = model.getPublicKeyRings();
                for (Model.PrimaryKey primaryKey : publicKeyRings) {
                    System.out.println(primaryKey.userId + " " + primaryKey.email + " " + Long.toHexString(primaryKey.keyId).toUpperCase());
                    if (primaryKey.subkey != null) {
                        System.out.println("\t" + Long.toHexString(primaryKey.subkey.keyId).toUpperCase());
                    }
                }
            } else if (command.indexOf("send message") == 0) {
                //send message <input file name> <output file name> <compression enabled>  <radix enabled> <secret key id> <passphrase> <encryption algoritham> <coma separated public key ids>
                String[] arguments = command.substring("send message".length() + 1).split(" ");
                if (arguments.length != 8) {
                    System.out.println("Invalid arguments");
                    continue;
                }
                String inputFilename = arguments[0];
                String outputFilename = arguments[1];
                Boolean compression = null;
                try {
                    compression = Boolean.parseBoolean(arguments[2]);
                } catch (NumberFormatException nfe) {
                    System.out.println("Invalid compression specification");
                    continue;
                }
                Boolean radix64 = null;
                try {
                    radix64 = Boolean.parseBoolean(arguments[3]);
                } catch (NumberFormatException nfe) {
                    System.out.println("Invalid compression");
                    continue;
                }

                Long secretKeyId = null;
                if (!"null".equals(arguments[4])) {
                    try {
                        BigInteger tmp = new BigInteger(arguments[4], 16);
                        secretKeyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                }
                String passphrase = arguments[5];

                String encryptionAlgoritham = arguments[6];
                if ("null".equals(encryptionAlgoritham)) {
                    encryptionAlgoritham = null;
                }

                List<Long> publicKayIdList = new ArrayList();
                String[] publicKeyIds = arguments[7].split(",");
                for (String publicKeyId : publicKeyIds) {
                    try {
                        BigInteger tmp = new BigInteger(publicKeyId, 16);
                        Long keyId = tmp.longValue();
                        publicKayIdList.add(keyId);
                    } catch (NumberFormatException nfe) {
                        System.out.println("Invalid public key id " + publicKeyId);
                        return;
                    }

                }

                model.sendMessage(outputFilename, inputFilename, encryptionAlgoritham, compression, radix64, secretKeyId, passphrase, publicKayIdList);
            } else if (command.indexOf("receive message") == 0) {
//                receive message <input file name> <output file name> <passphrase>
                String[] arguments = command.substring("receive message".length() + 1).split(" ");
                if (arguments.length < 2) {
                    System.out.println("Invalid arguments");
                    continue;
                }
                String inputFilename = arguments[0];
                List<Model.PrimaryKey> primaryKeys = model.findKeyId(inputFilename);

                Long secretKeyId = null;
                String passphrase = null;

                if (!primaryKeys.isEmpty()) {
                    System.out.println("Select subkey and enter passphrase:");
                    for (Model.PrimaryKey primaryKey : primaryKeys) {
                        System.out.println(primaryKey.userId + " " + primaryKey.email + " " + Long.toHexString(primaryKey.keyId) + " " + Long.toHexString(primaryKey.subkey.keyId));
                    }
                    String keyLine = scanner.nextLine();
                    String[] keyArguments = keyLine.split(" ");
                    if (keyArguments.length != 2) {
                        System.out.println("Invalid key arguments");
                        continue;
                    }

                    try {
                        BigInteger tmp = new BigInteger(keyArguments[0], 16);
                        secretKeyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                    passphrase = keyArguments[1];
                }

                String outputFilename = arguments[1];

//                String passphrase = null;
//                try {
//                    passphrase = arguments[2];
//                } catch (IndexOutOfBoundsException ioobe) {
//                }
                String message = model.receiveMessage(inputFilename, outputFilename, secretKeyId, passphrase);
                System.out.println(message);
            } else if (command.indexOf("import secret key") == 0) {
//                import secret key <input file name>
                String[] arguments = command.substring("import secret key".length() + 1).split(" ");
                if (arguments.length != 1) {
                    System.out.println("Invalid arguments");
                    continue;
                }
                String inputFilename = arguments[0];
                String message = model.importSecretKeys(inputFilename);
                System.out.println(message);
            } else if (command.indexOf("import public key") == 0) {
//                import public key <input file name>
                String[] arguments = command.substring("import public key".length() + 1).split(" ");
                if (arguments.length != 1) {
                    System.out.println("Invalid arguments");
                    continue;
                }
                String inputFilename = arguments[0];
                String message = model.importPublicKeys(inputFilename);
                System.out.println(message);
            } else if (command.indexOf("export secret key") == 0) {
//                export secret key <key id> <output file name>
                String[] arguments = command.substring("import secret key".length() + 1).split(" ");
                if (arguments.length != 2) {
                    System.out.println("Invalid arguments");
                    continue;
                }

                Long keyId = null;
                if (!"null".equals(arguments[0])) {
                    try {
                        BigInteger tmp = new BigInteger(arguments[0], 16);
                        keyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                }

                String outputFilename = arguments[1];
                String message = model.exportSecretKey(keyId, outputFilename);
                System.out.println(message);
            } else if (command.indexOf("export public key") == 0) {
//                export public key <input file name> <output file name>
                String[] arguments = command.substring("import public key".length() + 1).split(" ");
                if (arguments.length != 2) {
                    System.out.println("Invalid arguments");
                    continue;
                }

                Long keyId = null;
                if (!"null".equals(arguments[0])) {
                    try {
                        BigInteger tmp = new BigInteger(arguments[0], 16);
                        keyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                }

                String outputFilename = arguments[1];
                String message = model.exportPublicKey(keyId, outputFilename);
                System.out.println(message);
            } else if (command.indexOf("delete public key") == 0) {
//                delete public key <key id>
                String[] arguments = command.substring("delete public key".length() + 1).split(" ");
                if (arguments.length != 1) {
                    System.out.println("Invalid arguments");
                    continue;
                }

                Long keyId = null;
                if (!"null".equals(arguments[0])) {
                    try {
                        BigInteger tmp = new BigInteger(arguments[0], 16);
                        keyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                }

                String message = model.deletePublicKeyPair(keyId);
                System.out.println(message);
            } else if (command.indexOf("delete secret key") == 0) {
//                delete secret key <key id> <passphrase>
                String[] arguments = command.substring("delete secret key".length() + 1).split(" ");
                if (arguments.length != 2) {
                    System.out.println("Invalid arguments");
                    continue;
                }

                Long keyId = null;
                if (!"null".equals(arguments[0])) {
                    try {
                        BigInteger tmp = new BigInteger(arguments[0], 16);
                        keyId = tmp.longValue();
                    } catch (NumberFormatException nfe) {
                        System.err.println(nfe);
                        System.out.println("Invalid secret key id");
                        continue;
                    }
                }
                String passphrase = arguments[1];

                String message = model.deleteSecretKeyPair(keyId, passphrase);
                System.out.println(message);
            } else if (command.indexOf("quit") == 0) {
                return;
            } else {
                System.out.println("Invalid command");
            }
        }
    }
}
