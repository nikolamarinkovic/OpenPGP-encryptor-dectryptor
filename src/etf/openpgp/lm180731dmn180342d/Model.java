/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package etf.openpgp.lm180731dmn180342d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/**
 *
 * @author Fox
 */
public class Model {

    private static final String PUBLIC_KEY_RING_COLLECTION_FILENAME = "public.asc";
    private static final String SECRET_KEY_RING_COLLECTION_FILENAME = "secret.asc";
    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private PGPPublicKeyRingCollection pgpPublicKeyRingCollection;

    private static Model instance = null;

    public static Model getInstance() {
        if (instance == null) {
            instance = new Model();
        }
        return instance;
    }

    public Model() {
        Security.addProvider(new BouncyCastleProvider());

        FileInputStream publicKeyInputStream = null;
        try {
            File publicKeyFile = new File(PUBLIC_KEY_RING_COLLECTION_FILENAME);
            publicKeyFile.createNewFile();
            publicKeyInputStream = new FileInputStream(PUBLIC_KEY_RING_COLLECTION_FILENAME);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream), new JcaKeyFingerprintCalculator());
            publicKeyInputStream.close();
        } catch (IOException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }

        FileInputStream secretKeyInputStream = null;
        try {
            File secretKeyFile = new File(SECRET_KEY_RING_COLLECTION_FILENAME);
            secretKeyFile.createNewFile();
            secretKeyInputStream = new FileInputStream(SECRET_KEY_RING_COLLECTION_FILENAME);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyInputStream), new JcaKeyFingerprintCalculator());
        } catch (IOException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private PGPSecretKey findSecretKey(long keyID) {

        try {
            return pgpSecretKeyRingCollection.getSecretKey(keyID);
        } catch (PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private PGPPrivateKey decryptSecretKey(PGPSecretKey pgpSecKey, char[] pass) {
        try {
            return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        } catch (PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private PGPPublicKey findPublicKey(long publicKeyId) {
        try {
            PGPPublicKey publicKey = pgpPublicKeyRingCollection.getPublicKey(publicKeyId);
            if (publicKey == null) {
                publicKey = pgpSecretKeyRingCollection.getSecretKey(publicKeyId).getPublicKey();
            }
            return publicKey;
        } catch (PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String sendMessage(
            String outputFilename,
            String inputFilename,
            String encryptionAlgoritham,
            boolean compress,
            boolean radix64,
            Long secretKeyID,
            String passphrase,
            List<Long> publicKeyIDList) {

        try {

            InputStream cleartext = new FileInputStream(inputFilename);

            OutputStream fileOutputStream = new FileOutputStream(outputFilename);

            OutputStream pgpMessage = fileOutputStream;

            OutputStream radixOutputStream = null;
            if (radix64) {
                radixOutputStream = new ArmoredOutputStream(pgpMessage);
                pgpMessage = radixOutputStream;
            }

            OutputStream encryptionOutputStream = null;
            PGPEncryptedDataGenerator encryptedDataGenerator = null;
            if (!publicKeyIDList.isEmpty()) {
                int encryptionAlgorithamId = -1;
                if ("AES128".equals(encryptionAlgoritham)) {
                    encryptionAlgorithamId = PGPEncryptedData.AES_128;
                } else if ("3DES".equals(encryptionAlgoritham)) {
                    encryptionAlgorithamId = PGPEncryptedData.TRIPLE_DES;
                } else {
                    return "Invalid encryption algoritham";
                }
                encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(encryptionAlgorithamId).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));

                for (long publicKey : publicKeyIDList) {
                    PGPPublicKey pgpPublicKey = findPublicKey(publicKey);
                    if (pgpPublicKey == null) {
                        return "Public key with id " + Long.toHexString(publicKey) + "does not exist";
                    }
                    encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
                }

                encryptionOutputStream = encryptedDataGenerator.open(pgpMessage, new byte[1 << 16]);
                pgpMessage = encryptionOutputStream;
            }

            OutputStream compressOutputStream = null;
            PGPCompressedDataGenerator comData = null;
            if (compress) {
                comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                compressOutputStream = comData.open(pgpMessage);
                pgpMessage = compressOutputStream;
            }

            if (secretKeyID != null) {
                PGPSecretKeyRing secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(secretKeyID);
                if (secretKeyRing == null) {
                    return "Secret key with id " + Long.toHexString(secretKeyID) + "does not exist";
                }
                PGPSecretKey pgpSec = secretKeyRing.getSecretKey(secretKeyID);
                if (pgpSec == null) {
                    return "Secret key with id " + Long.toHexString(secretKeyID) + "does not exist";
                }
                PGPPrivateKey pgpPrivKey = decryptSecretKey(pgpSec, passphrase.toCharArray());
                if (pgpPrivKey == null) {
                    return "Wrong password for secret key";
                }
                PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

                sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

                Iterator it = pgpSec.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

                    spGen.addSignerUserID(false, (String) it.next());
                    sGen.setHashedSubpackets(spGen.generate());
                }

                sGen.generateOnePassVersion(false).encode(pgpMessage);

                File file = new File(inputFilename);
                PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
                OutputStream literDataOutputStream = lGen.open(pgpMessage, PGPLiteralData.BINARY, file);
                int ch;
                while ((ch = cleartext.read()) >= 0) {
                    literDataOutputStream.write(ch);
                    sGen.update((byte) ch);
                }

                literDataOutputStream.close();
                lGen.close();

                sGen.generate().encode(pgpMessage);

            } else {
                PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
                OutputStream literDataOutputStream = lGen.open(pgpMessage, PGPLiteralData.BINARY, new File(inputFilename));
                int ch;
                while ((ch = cleartext.read()) >= 0) {
                    literDataOutputStream.write(ch);
                }
                literDataOutputStream.close();
                lGen.close();
            }

            if (compress) {
                compressOutputStream.close();
                comData.close();
            }
            if (!publicKeyIDList.isEmpty()) {
                encryptionOutputStream.close();
                encryptedDataGenerator.close();
            }
            if (radix64) {
                radixOutputStream.close();
            }

            fileOutputStream.close();
            cleartext.close();

            return "Success";
        } catch (FileNotFoundException ex) {
            return "Input file does not exist";
        } catch (IOException | PGPException e) {
            return "Internal error";
        }
    }

    public void generateKeyPairs(String userId, String pass, Integer DSAKeySize, Integer ElGamalKeySize) {
        try {
            KeyPairGenerator DSAKeyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
            DSAKeyPairGenerator.initialize(DSAKeySize);
            KeyPair DSAKeyPair = DSAKeyPairGenerator.generateKeyPair();
            PGPKeyPair DSApgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, DSAKeyPair, new Date());
            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION,
                    DSApgpKeyPair,
                    userId,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(
                            DSApgpKeyPair.getPublicKey().getAlgorithm(),
                            HashAlgorithmTags.SHA1
                    ),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(pass.toCharArray())
            );

            if (ElGamalKeySize != null) {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ELGAMAL", "BC");
                BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
                BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);
                DHParameterSpec ELGamalParameters = new DHParameterSpec(p, g);
                keyPairGenerator.initialize(ELGamalParameters);
                keyPairGenerator.initialize(ElGamalKeySize);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());
                keyRingGen.addSubKey(pgpKeyPair);
            }

            pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRingCollection, keyRingGen.generateSecretKeyRing());
            saveKeyRingCollections();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String deleteSecretKeyPair(long keyId, String passphrase) {
        try {
            PGPSecretKeyRing oldSecretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            if (oldSecretKeyRing != null) {
                PGPSecretKey secretKey = oldSecretKeyRing.getSecretKey(keyId);
                if (decryptSecretKey(secretKey, passphrase.toCharArray()) == null) {
                    return "Wrong password for secret key";
                }
                pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.removeSecretKeyRing(pgpSecretKeyRingCollection, oldSecretKeyRing);
                saveKeyRingCollections();
                return "Success";
            }
            PGPPublicKeyRing publicKeyRing = pgpPublicKeyRingCollection.getPublicKeyRing(keyId);
            if (publicKeyRing != null) {
                return "Can't delete public key as private key";
            }
            return "Key ring not found";
        } catch (PGPException ex) {
            return "Internal error";
        }
    }

    public String deletePublicKeyPair(long keyId) {
        try {
            PGPPublicKeyRing oldPublicKeyRing = pgpPublicKeyRingCollection.getPublicKeyRing(keyId);
            if (oldPublicKeyRing != null) {
                pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.removePublicKeyRing(pgpPublicKeyRingCollection, oldPublicKeyRing);
                saveKeyRingCollections();
                return "Success.";
            }
            PGPSecretKeyRing secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            if (secretKeyRing != null) {
                return "Can't delete private key as private key";
            }
            return "Key ring not found";
        } catch (PGPException ex) {
            return "Internal error";
        }
    }

    private void saveKeyRingCollections() {
        try {
            OutputStream publicKeyRingCollectionOutputStream = new FileOutputStream(PUBLIC_KEY_RING_COLLECTION_FILENAME);
            publicKeyRingCollectionOutputStream = new ArmoredOutputStream(publicKeyRingCollectionOutputStream);
            pgpPublicKeyRingCollection.encode(publicKeyRingCollectionOutputStream);
            publicKeyRingCollectionOutputStream.close();

            OutputStream secretKeyRingCollectionOutputStream = new FileOutputStream(SECRET_KEY_RING_COLLECTION_FILENAME);
            secretKeyRingCollectionOutputStream = new ArmoredOutputStream(secretKeyRingCollectionOutputStream);
            pgpSecretKeyRingCollection.encode(secretKeyRingCollectionOutputStream);
            secretKeyRingCollectionOutputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public List<PrimaryKey> getSecretKeyRings() {
        List<PrimaryKey> primaryKeys = new ArrayList();
        Pattern r = Pattern.compile("(.+)<(.+)>");
        for (PGPSecretKeyRing secretKeyRing : pgpSecretKeyRingCollection) {
            Iterator<PGPSecretKey> iterator = secretKeyRing.iterator();
            PGPSecretKey primarySecretKey = iterator.next();
            String userId = primarySecretKey.getUserIDs().next();
            Matcher m = r.matcher(userId);
            m.find();
            PrimaryKey primaryKey = new PrimaryKey(primarySecretKey.getKeyID(), m.group(1), m.group(2));

            if (iterator.hasNext()) {
                PGPSecretKey subSecretKey = iterator.next();
                Subkey subkey = new Subkey(subSecretKey.getKeyID(), primaryKey);
                primaryKey.subkey = subkey;
            }
            primaryKeys.add(primaryKey);
        }
        return primaryKeys;
    }

    public List<PrimaryKey> getPublicKeyRings() {
        List<PrimaryKey> primaryKeys = new ArrayList();
        Pattern r = Pattern.compile("(.+)<(.+)>");
        for (PGPPublicKeyRing publicKeyRing : pgpPublicKeyRingCollection) {
            Iterator<PGPPublicKey> iterator = publicKeyRing.iterator();
            PGPPublicKey primaryPublicKey = iterator.next();
            Matcher m = r.matcher(primaryPublicKey.getUserIDs().next());
            m.find();
            PrimaryKey primaryKey = new PrimaryKey(primaryPublicKey.getKeyID(), m.group(1), m.group(2));

            if (iterator.hasNext()) {
                PGPPublicKey subPublicKey = iterator.next();
                Subkey subkey = new Subkey(subPublicKey.getKeyID(), primaryKey);
                primaryKey.subkey = subkey;
            }
            primaryKeys.add(primaryKey);
        }
        return primaryKeys;
    }

    public String receiveMessage(String inputFilename, String outputFilename, Long secretKeyId, String passphrase) {
        String message = "";
        try {
            InputStream fileInputStream = new FileInputStream(inputFilename);
            InputStream radixInputStream = PGPUtil.getDecoderStream(fileInputStream); //radix

            PGPObjectFactory pgpF = new JcaPGPObjectFactory(radixInputStream);

            Object tmpObject = pgpF.nextObject();

            PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
            if (tmpObject instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) tmpObject;
//                System.out.println("Velicina liste: " + encryptedDataList.size());

                publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(0);

                for (PGPEncryptedData keyEncryptedData : encryptedDataList) {
                    if (keyEncryptedData instanceof PGPPublicKeyEncryptedData) {
                        PGPPublicKeyEncryptedData tmpEncryptedData = (PGPPublicKeyEncryptedData) keyEncryptedData;
                        if (tmpEncryptedData.getKeyID() == secretKeyId) {
                            publicKeyEncryptedData = tmpEncryptedData;
                            break;
                        }
                    }
                }
                if (publicKeyEncryptedData == null) {
                    return "Invalid secret key id";
                }

                PGPSecretKey secretKey = findSecretKey(publicKeyEncryptedData.getKeyID());
                if (secretKey == null) {
                    return "Secret key does not exist";
                }
                PGPPrivateKey privateKey = decryptSecretKey(secretKey, passphrase.toCharArray());
                if (privateKey == null) {
                    return "Invalid passphrase";
                }
                InputStream dataStream = publicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
                pgpF = new JcaPGPObjectFactory(dataStream);
                tmpObject = pgpF.nextObject();
                message += "Decrypted<br>";
            }

            if (tmpObject instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) tmpObject;
                InputStream compressedStream = compressedData.getDataStream();
                pgpF = new JcaPGPObjectFactory(compressedStream);
                tmpObject = pgpF.nextObject();
                message += "Decompressed<br>";
            }

            PGPOnePassSignature onePassSignature = null;
            if (tmpObject instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) tmpObject;
                onePassSignature = onePassSignatureList.get(0);
                PGPPublicKey publicKey = findPublicKey(onePassSignature.getKeyID());
                onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                tmpObject = pgpF.nextObject();
            }

            if (tmpObject instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) tmpObject;

                InputStream cleartext = ld.getInputStream();
                OutputStream fileOutputStream = new FileOutputStream(outputFilename);

                int ch;
                while ((ch = cleartext.read()) >= 0) {
                    if (onePassSignature != null) {
                        onePassSignature.update((byte) ch);
                    }
                    fileOutputStream.write(ch);
                }

                fileOutputStream.close();
                tmpObject = pgpF.nextObject();
            }

            if (tmpObject instanceof PGPSignatureList) {
                PGPSignatureList signatureList = (PGPSignatureList) tmpObject;
                PGPSignature signature = signatureList.get(0);
                if (onePassSignature != null) {
                    if (onePassSignature.verify(signature)) {
                        message += "Signature verification success<br>";
                    } else {
                        message += "Signature verification failed<br>";
                    }

                }
            }

            if (publicKeyEncryptedData != null && publicKeyEncryptedData.isIntegrityProtected()) {
                Boolean verify = publicKeyEncryptedData.verify();
                if (verify) {
                    message += "Integrity verified<br>";
                } else {
                    message += "Integrity verification failed";
                }
            }
            radixInputStream.close();
            return message;
        } catch (FileNotFoundException ex) {
            return "";
//            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | PGPException ex) {
            Logger.getLogger(Model.class.getName()).log(Level.SEVERE, null, ex);
            return "";
        }
    }

    public List<PrimaryKey> findKeyId(String inputFilename) {
        List<PrimaryKey> primaryKeys = new ArrayList<>();
        try {
            InputStream in = new FileInputStream(inputFilename);
            in = PGPUtil.getDecoderStream(in); //radix

            PGPObjectFactory pgpF = new JcaPGPObjectFactory(in);

            Object tmpObject = pgpF.nextObject();

            if (tmpObject instanceof PGPEncryptedDataList) {
                Pattern r = Pattern.compile("(.+)<(.+)>");
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) tmpObject;
                for (PGPEncryptedData keyEncryptedData : encryptedDataList) {
                    PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) keyEncryptedData;
                    PGPSecretKeyRing secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(publicKeyEncryptedData.getKeyID());
                    if (secretKeyRing != null) {
                        Iterator<PGPSecretKey> iterator = secretKeyRing.iterator();
                        PGPSecretKey primarySecretKey = iterator.next();
                        String userId = primarySecretKey.getUserIDs().next();
                        Matcher m = r.matcher(userId);
                        m.find();
                        PrimaryKey primaryKey = new PrimaryKey(primarySecretKey.getKeyID(), m.group(1), m.group(2));

                        if (iterator.hasNext()) {
                            PGPSecretKey subSecretKey = iterator.next();
                            Subkey subkey = new Subkey(subSecretKey.getKeyID(), primaryKey);
                            primaryKey.subkey = subkey;
                        }
                        primaryKeys.add(primaryKey);
                    }
                }
            }
            return primaryKeys;
        } catch (IOException | PGPException ex) {
            return null;
        }
    }

    public String exportPublicKey(long keyId, String filename) {
        try {
            PGPPublicKeyRing publicKeyRing = null;
            PGPSecretKeyRing secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            if (secretKeyRing != null) {
                Iterator<PGPPublicKey> publicKeysIterator = secretKeyRing.getPublicKeys();
                List<PGPPublicKey> publicKeysList = new ArrayList<>();
                while (publicKeysIterator.hasNext()) {
                    publicKeysList.add(publicKeysIterator.next());
                }
                publicKeyRing = new PGPPublicKeyRing(publicKeysList);
            } else {
                publicKeyRing = pgpPublicKeyRingCollection.getPublicKeyRing(keyId);
            }
            if (publicKeyRing == null) {
                return "Key not found";
            }
            OutputStream out = new ArmoredOutputStream(new FileOutputStream(filename));
            publicKeyRing.encode(out);
            out.close();
            return "Success";
        } catch (IOException | PGPException ex) {
            return "Internal error";
        }
    }

    public String exportSecretKey(long keyId, String filename) {
        try {
            OutputStream out = new ArmoredOutputStream(new FileOutputStream(filename));
            PGPSecretKeyRing secretKeyRing = pgpSecretKeyRingCollection.getSecretKeyRing(keyId);
            if (secretKeyRing == null) {
                return "Key not found";
            }
            secretKeyRing.encode(out);
            out.close();
            return "Success";
        } catch (PGPException | IOException ex) {
            return "Internal error";
        }
    }

    public String importPublicKeys(String inputFilename) {
        FileInputStream fileInputStream = null;
        String message = "";
        int count = 0;
        try {
            fileInputStream = new FileInputStream(inputFilename);
            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(fileInputStream),
                    new JcaKeyFingerprintCalculator()
            );
            for (PGPPublicKeyRing publicKeyRing : pgpPub) {
                PGPKeyRing keyRingOld = pgpPublicKeyRingCollection.getPublicKeyRing(publicKeyRing.getPublicKey().getKeyID());
                if (keyRingOld == null) {
                    keyRingOld = pgpSecretKeyRingCollection.getSecretKeyRing(publicKeyRing.getPublicKey().getKeyID());
                }
                if (keyRingOld != null) {
                    String user = "";
                    String primaryKeyId = "";
                    String subKeyId = "";
                    Iterator<PGPPublicKey> publicKeys = keyRingOld.getPublicKeys();
                    if (publicKeys.hasNext()) {
                        PGPPublicKey publicKey = publicKeys.next();
                        Iterator<String> userIDs = publicKey.getUserIDs();
                        if (userIDs.hasNext()) {
                            user = userIDs.next();
                        }
                        primaryKeyId = Long.toHexString(publicKey.getKeyID());
                    }
                    if (publicKeys.hasNext()) {
                        PGPPublicKey publicKey = publicKeys.next();
                        subKeyId = Long.toHexString(publicKey.getKeyID());
                    }
                    message += "Keyring with user " + user + " and key ids" + " already exists<br>";
                } else {
                    pgpPublicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPublicKeyRingCollection, publicKeyRing);
                    count++;
                }
            }
            fileInputStream.close();
            saveKeyRingCollections();
            message += "Imported " + count + "key rings";
            return message;
        } catch (FileNotFoundException ex) {
            return "Input file does not exist";
        } catch (IOException | PGPException ex) {
            return "Internal error";
        }
    }

    public String importSecretKeys(String inputFilename) {
        try {
            int count = 0;
            String message = "";
            FileInputStream fileInputStream = new FileInputStream(inputFilename);
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(fileInputStream),
                    new JcaKeyFingerprintCalculator()
            );
            for (PGPSecretKeyRing secretKeyRing : pgpSec) {
                PGPKeyRing keyRingOld = pgpPublicKeyRingCollection.getPublicKeyRing(secretKeyRing.getPublicKey().getKeyID());
                if (keyRingOld == null) {
                    keyRingOld = pgpSecretKeyRingCollection.getSecretKeyRing(secretKeyRing.getPublicKey().getKeyID());
                }
                if (keyRingOld != null) {
                    String user = "";
                    String primaryKeyId = "";
                    String subKeyId = "";
                    Iterator<PGPPublicKey> publicKeys = keyRingOld.getPublicKeys();
                    if (publicKeys.hasNext()) {
                        PGPPublicKey publicKey = publicKeys.next();
                        Iterator<String> userIDs = publicKey.getUserIDs();
                        if (userIDs.hasNext()) {
                            user = userIDs.next();
                        }
                        primaryKeyId = Long.toHexString(publicKey.getKeyID());
                    }
                    if (publicKeys.hasNext()) {
                        PGPPublicKey publicKey = publicKeys.next();
                        subKeyId = Long.toHexString(publicKey.getKeyID());
                    }
                    message += "Key ring with user " + user + " and key ids" + " already exists<br>";
                } else {
                    pgpSecretKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(pgpSecretKeyRingCollection, secretKeyRing);
                    count++;
                }
            }
            fileInputStream.close();
            saveKeyRingCollections();
            message += "Imported " + count + "key rings";
            return message;
        } catch (FileNotFoundException ex) {
            return "Input file does not exist";
        } catch (IOException | PGPException ex) {
            return "Internal error";

        }
    }

    public static class Subkey {

        public Long keyId;
        public PrimaryKey primaryKey;

        public Subkey(Long keyId, PrimaryKey primaryKey) {
            this.keyId = keyId;
            this.primaryKey = primaryKey;
        }

    }

    public static class PrimaryKey {

        public Long keyId;
        public String userId;
        public String email;
        public Subkey subkey;

        public PrimaryKey(Long keyId, String userId, String email) {
            this.keyId = keyId;
            this.userId = userId;
            this.email = email;
        }

    }

}
