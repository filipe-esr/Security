import java.io.File;
import java.io.FileInputStream;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClientSecurity {
    
    static PublicKey pubkey = null;
    static private PrivateKey privkey = null;
    static private SecretKey secretKey = null;
    
    // build the initialization vector.  This example is all zeros, but it 
    // values generated using a random number generator
    byte[] iv = { 6, 1, 7, 1, 3, 3, 9, 3, 5, 5, 5, 5, 5, 8, 9, 2 };
    IvParameterSpec ivspec = new IvParameterSpec(iv);
    
    // CHAVES ASSIMETRICAS -----------------------------------------------------
    public PublicKey generateAsymKey() throws NoSuchAlgorithmException{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        pubkey = keyPair.getPublic();
        privkey = keyPair.getPrivate();
        return pubkey;
    }

    public PublicKey getPubKey(){
        return pubkey;
    }
    
    public PrivateKey getPrivateKey(){
        return privkey;
    }
    
    public void setPubKey(PublicKey key){
        pubkey = key;
    }
    
    public void setPrivateKey(PrivateKey key){
        privkey = key;
    }
    
    public static byte[] encryptAsym(PublicKey publickey, String msg) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publickey);
        return cipher.doFinal(msg.getBytes());
    }
    
    public static byte[] encryptAsymPrivKey(String msg) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privkey);
        return cipher.doFinal(msg.getBytes());
    }
    
    public static byte[] encryptAsym(PublicKey publickey, byte[] msg) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publickey);
        return cipher.doFinal(msg);
    }

    public static byte[] decryptAsym(byte[] msgEncrypted) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privkey);
        return cipher.doFinal(msgEncrypted);
    }
    
    public static byte[] decryptAsymPubKey(PublicKey publickey, byte[] msgEncrypted) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publickey);
        return cipher.doFinal(msgEncrypted);
    }
    
    public static String sign(String msg) {
        byte[] signature = null;
        try{
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privkey);
            privateSignature.update(msg.getBytes(UTF_8));
            signature = privateSignature.sign();
        }catch(Exception e){
            System.err.println(e);
        }
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(PublicKey publicKey, String msg, String signature) throws Exception{
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(msg.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }
    
    // CHAVES SIMETRICAS -------------------------------------------------------
    public SecretKey createKeyAES(){
        /*Creation of a secret Key using AES algorithm*/
        try{  
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        }catch(Exception e){
            System.out.println(e);
        }
        return secretKey;
    }

    public SecretKey createKeyAES_hybMSG(){
        /*Creation of a secret Key using AES algorithm*/
        SecretKey sk = null;
        try{  
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            sk = keyGen.generateKey();
        }catch(Exception e){
            System.out.println(e);
        }
        return sk;
    }
    
    public SecretKey getKeyAES(){
        return secretKey;
    }

    public byte[] EncryptAES(String msg){
        byte[] cipherText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            cipherText = c.doFinal(msg.getBytes());
        }catch(Exception e){
            System.out.println(e);
        }
        return cipherText;
    }
    
    public byte[] EncryptAES(SecretKey sk, String msg){
        byte[] cipherText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, sk, ivspec);
            cipherText = c.doFinal(msg.getBytes());
        }catch(Exception e){
            System.out.println(e);
        }
        return cipherText;
    }
    
    public byte[] EncryptAES(byte[] msg){
        byte[] cipherText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            cipherText = c.doFinal(msg);
        }catch(Exception e){
            System.out.println(e);
        }
        return cipherText;
    }

    public byte[] DecryptAES(byte[] msg){
        byte[] decipheredText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            decipheredText = c.doFinal(msg);
        }catch(Exception e){
            System.out.println(e);
        }
        return decipheredText; 
    }
    
    public byte[] DecryptAES(SecretKey sk, byte[] msg){
        byte[] decipheredText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, sk, ivspec);
            decipheredText = c.doFinal(msg);
        }catch(Exception e){
            System.out.println(e);
        }
        return decipheredText; 
    }
    
    // CALCULATE HMAC ----------------------------------------------------------
    public byte[] calculateHMAC(byte[] original, SecretKey sk){
        byte[] hmac = null;
        try{
            SecretKeySpec secretKeySpec = new SecretKeySpec(sk.getEncoded(),"HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKeySpec);
            hmac = mac.doFinal(original);
        }catch(NoSuchAlgorithmException | InvalidKeyException | IllegalStateException e){
            System.err.println(e);
        }
        return hmac;
    }
    
    // CALCULATE UNIQUE ID USING CC --------------------------------------------
    public byte[] generateHashCC(){
        String CC_KEY_1 = "CITIZEN AUTHENTICATION CERTIFICATE";
        String ccpath = "CitizenCard.cfg";
        byte[] hash = null;
        try{
        Provider p = new sun.security.pkcs11.SunPKCS11(ccpath);
        Security.addProvider(p);

        KeyStore ks = KeyStore.getInstance("PKCS11","SunPKCS11-PTeID");
        ks.load(null,null);
        PrivateKey privateKey = (PrivateKey) ks.getKey(CC_KEY_1,null);
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        hash = digest.digest(cipher.doFinal("id".getBytes()));
        
        }catch(Exception e){
            System.err.println("No CC detected. Exception: " + e);
        }
        return hash;
    }
    
    public X509Certificate getCertificate(){
        X509Certificate cert = null;
        try{
        String ccpath = "CitizenCard.cfg";
        Provider p = new sun.security.pkcs11.SunPKCS11(ccpath);
        Security.addProvider(p);

        KeyStore ks = KeyStore.getInstance("PKCS11","SunPKCS11-PTeID");
        ks.load(null,null);
        cert = (X509Certificate) ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        }catch(Exception e){System.err.println("No CC detected."); return null;}
        return cert;
    }
    
    static boolean validateCertificates(X509Certificate INcert){
        ArrayList<X509Certificate> anchors = new ArrayList<X509Certificate>();
        ArrayList<X509Certificate> intermediates = new ArrayList<X509Certificate>();
        try{
        FileInputStream input = new FileInputStream(new File("CC_KS"));
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "password";
            ks.load(input, password.toCharArray());
            
            Enumeration<String> Enum = ks.aliases();
            while(Enum.hasMoreElements()){
                String alias = Enum.nextElement();
                //System.out.println("ALIAS: "+alias);
                java.security.cert.Certificate cert = ks.getCertificate(alias);
                PublicKey key = cert.getPublicKey();
                try{
                    cert.verify(key);
                    anchors.add((X509Certificate) ks.getCertificate(alias));
                }catch(Exception e){
                    intermediates.add((X509Certificate) ks.getCertificate(alias));
                }  
            }
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(INcert);
            Set<TrustAnchor> subsetAnchors = new HashSet<TrustAnchor>();
            
            for(X509Certificate anchor: anchors){
                TrustAnchor trustAnchor = new TrustAnchor(anchor,null);
                subsetAnchors.add(trustAnchor);
            }
          
            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(subsetAnchors, selector);
            pkixParams.setRevocationEnabled(false); //No CRL checking
            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(intermediates);
            CertStore intermediateCertStore = CertStore.getInstance("Collection", ccsp);
            pkixParams.addCertStore(intermediateCertStore);
            
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult path = (PKIXCertPathBuilderResult) builder.build(pkixParams);
            
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            PKIXParameters validationParams = new PKIXParameters(subsetAnchors);
            validationParams.setRevocationEnabled(false);
            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            Date date = new Date();
            dateFormat.format(date); //2016/11/16 12:08:43
            //System.out.println(date.toString());
            validationParams.setDate(date);
            try{    
                cpv.validate(path.getCertPath(),validationParams);
            }catch(Exception e){e.printStackTrace();
            return false;}
            
        }catch(Exception e){e.printStackTrace(); }         
        return true;
    }
}
