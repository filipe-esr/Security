import java.net.Socket;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class ServerActions implements Runnable {

    boolean registered = false;
    Socket client;
    JsonReader in;
    OutputStream out;
    ServerControl registry;
    SecretKey clientAESKey;
    byte[] iv = { 6, 1, 7, 1, 3, 3, 9, 3, 5, 5, 5, 5, 5, 8, 9, 2 };
    IvParameterSpec ivspec = new IvParameterSpec(iv);
    String msgRandom;
    int authID = -1;
    
    ServerActions ( Socket c, ServerControl r ) {
        client = c;
        registry = r;

        try {
            in = new JsonReader( new InputStreamReader ( c.getInputStream(), "UTF-8") );
            out = c.getOutputStream();
        } catch (Exception e) {
            System.err.print( "Cannot use client socket: " + e );
            Thread.currentThread().interrupt();
        }
    }

    JsonObject
    readCommand () {
        try {
            JsonElement data = new JsonParser().parse( in );
            if (data.isJsonObject()) {
                return data.getAsJsonObject();
            }
            System.err.print ( "Error while reading command from socket (not a JSON object), connection will be shutdown\n" );
            return null;
        } catch (JsonIOException e){
            System.out.println(e);
            System.err.println("JsonIOException");
            return null;
        }catch(JsonSyntaxException e) {
            System.out.println(e);
            System.err.println("JsonSyntaxException");
            //System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
            return null;
        } /*catch (Exception e) {
            System.out.println(e);
            System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
            return null;
        }*/
    }

    void
    sendResult ( String result, String error ) {
        String msg = "{";

        // Usefull result

        if (result != null) {
            msg += result;
        }

        // error message

        if (error != null) {
            msg += "\"error\":" + error;
        }

        msg += "}\n";
        
        try {
            System.out.print( "Send result: " + msg );
            /* Stuff para 2 msg json */
            byte[] newMSG = EncryptAES(msg);
            byte[] mac_json = calculateHMAC(newMSG,clientAESKey);
            String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
            out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
        } catch (Exception e ) {
            System.err.println(e);
        }
    }

    void
    sendResultInit ( String result, String error ) {
        String msg = "{";

        // Usefull result

        if (result != null) {
            msg += result;
        }

        // error message

        if (error != null) {
            msg += "\"error\":" + error;
        }

        msg += "}\n";
        
        try {
            System.out.print( "Send result: " + msg );
            out.write (msg.getBytes( StandardCharsets.UTF_8 ));
        } catch (Exception e ) {}
    }
    
    void
    executeCommand ( JsonObject data ) {
        JsonElement cmd = data.get( "type" );
        if(!cmd.getAsString().equals("askServerPK") && !cmd.getAsString().equals("sendServerAES")){
            /* Tratamento da nova mensagem JSON */
            JsonElement json = data.get("json");
            /* A Verificar Integridade e Autenticidade da mensagem - HMAC-SHA1 (Encrypt-then-MAC -> Antes de desincriptar) */
            /* JsonElement para byte[] */
            byte[] tmp_json = Base64.getDecoder().decode(json.getAsString());
            /* Calcular HMAC aqui no server da mensagem encriptada e com a chave privada*/
            byte[] serverHMAC_json = calculateHMAC(tmp_json,clientAESKey);
            /* Obter o HMAC que o cliente manda na mesagem encriptada */
            byte[] clientHMAC_json = Base64.getDecoder().decode(data.get("hmac").getAsString());
            /* Comparar os dois HMAC a ver se são iguais, caso sejam diferentes a mensagem foi comprometida */
            if (!Arrays.equals(serverHMAC_json, clientHMAC_json)){
                System.err.println("Message Compromised!");
                sendResult( null, "\"message integrity compromised\"" );
                return;
            }
            /* Passagem de 2Json para Json original */
            byte[] tmp_newMsgJson = Base64.getDecoder().decode(json.getAsString());
            String msgJson = new String(DecryptAES(tmp_newMsgJson),StandardCharsets.UTF_8);
            data = new JsonParser().parse(msgJson).getAsJsonObject();
            
            cmd = data.get("type");
            
            UserDescription me;
            
            if (cmd == null) {
                System.err.println ( "Invalid command in request: " + data );
                return;
            }
            
            // CREATE
            if (cmd.getAsString().equals( "create" )) {
                JsonElement uuid = data.get( "uuid" );
                
                if (uuid == null) {
                    System.err.print ( "No \"uuid\" field in \"create\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                JsonElement flag = data.get( "cc" );
                
                byte[] temp_uuid = Base64.getDecoder().decode(uuid.getAsString());
                data.remove("uuid");
                if(flag.equals("false"))
                    data.addProperty("uuid", Base64.getEncoder().encodeToString(temp_uuid));
                else
                    data.addProperty("uuid", new String(temp_uuid,StandardCharsets.UTF_8));
                uuid = data.get( "uuid" );
                
                JsonElement pk = data.get( "pk" );

                if (pk == null) {
                    System.err.print ( "No \"pk\" field in \"create\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                try{
                //byte[] ola = data.get("cert").getAsString().getBytes();
                byte[] ola = Base64.getDecoder().decode(data.get("cert").getAsString());
                String stringOla = new String(ola,StandardCharsets.UTF_8);
                if(!stringOla.equals("")){
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream inStream = new ByteArrayInputStream(ola);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                if(!validateCertificates(cert)){
                    System.err.print ( "Invalid certificate: " + data );
                    sendResult( null, "\"Invalid certificate\"" );
                    return;
                }
                //System.out.println(cert);
                }
                
                }catch(Exception e){e.printStackTrace();}
                
                int msgIdentifier = data.get("ctr").getAsInt();
                if (registry.userExists( uuid.getAsString() )) {
                    System.err.println ( "User already exists: " + data );
                    me = registry.findUser(uuid.getAsString());
                    String publicKeyString = me.getPublicKeyRSA();
                    
                    byte[] msg = null;
                    try{
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = kf.generatePublic(spec); 
                    msgRandom = generateString();
                    authID = me.id;
                    msg = encryptAsym(publicKey, msgRandom);
                    System.out.println(new String(msg,StandardCharsets.UTF_8));
                    }catch(Exception e){
                        System.err.println(e);
                    }
                    sendResult("\"result\":\"authChallenge\", \"msg\":\""+Base64.getEncoder().encodeToString(msg)+"\", \"ctr\":\""+msgIdentifier+"\"",null);
                    return;
                }

                data.remove ( "type" );
                me = registry.addUser( data );
                authID = me.id;

                sendResult( "\"result\":\"" + me.id + "\",\"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }
            
            //authResponse
            if (cmd.getAsString().equals("authResponse")){
                int msgIdentifier = data.get("ctr").getAsInt();
                String msg = data.get("msg").getAsString();
                if(msg.equals(msgRandom)){
                    sendResult("\"result\":\""+authID+"\", \"ctr\":\""+msgIdentifier+"\"",null);
                }else{
                    authID = -1;
                    sendResult(null,"\"Authentication Failed - Bad Challenge Response\"");
                }
                return;
            }
            
            // LIST
            if (cmd.getAsString().equals( "list" )) {
                String list;
                int user = 0; // 0 means all users
                JsonElement id = data.get( "id" );

                if (id != null) {
                    user = id.getAsInt();
                }

                System.out.println( "List " + (user == 0 ? "all users" : "user ") + user );

                list = registry.listUsers( user );
                int msgIdentifier = data.get("ctr").getAsInt();
                sendResult( "\"data\":" + (list == null ? "[]" : list)+", \"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }

            // NEW
            if (cmd.getAsString().equals( "new" )) {
                JsonElement id = data.get( "id" );
                int msgIdentifier = data.get("ctr").getAsInt();
                
                if(authID != id.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                int user = id == null ? -1 : id.getAsInt();
                
                if (id == null || user <= 0) {
                    System.err.print ( "No valid \"id\" field in \"new\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }

                sendResult( "\"result\":" + registry.userNewMessages( user ) +",\"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }

            // ALL
            if (cmd.getAsString().equals( "all" )) {
                JsonElement id = data.get( "id" );
                int msgIdentifier = data.get("ctr").getAsInt();
                if(authID != id.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                int user = id == null ? -1 : id.getAsInt();
                
                sendResult( "\"result\":[" + registry.userAllMessages( user ) + "," +
                            registry.userSentMessages( user ) + "], \"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }
            
            // SEND
            if (cmd.getAsString().equals( "send" )) {
                JsonElement src = data.get( "src" );
                JsonElement dst = data.get( "dst" );
                JsonElement msg = data.get( "msg" );
                JsonElement copy = data.get( "copy" );
                JsonElement sign = data.get( "sign" );
                JsonElement sk = data.get( "key" );
                int msgIdentifier = data.get("ctr").getAsInt();
                
                if (src == null || dst == null || msg == null || copy == null || sign == null || sk == null) {
                    System.err.print ( "Badly formated \"send\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                if(authID != src.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                
                int srcId = src.getAsInt();
                int dstId = dst.getAsInt();

                if (registry.userExists( srcId ) == false) {
                    System.err.print ( "Unknown source id for \"send\" request: " + data );
                    sendResult( null, "\"wrong parameters\"" );
                    return;
                }
                
                if (registry.userExists( dstId ) == false) {
                    System.err.print ( "Unknown destination id for \"send\" request: " + data );
                    sendResult( null, "\"wrong parameters\"" );
                    return;
                }

                // Save message and copy
                String response = registry.sendMessage( srcId, dstId,
                                                        msg.getAsString(),
                                                        copy.getAsString(),
                                                        sign.getAsString(),
                                                        sk.getAsString());

                sendResult( "\"result\":" + response + ",\"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }

            // RECV
            if (cmd.getAsString().equals( "recv" )) {
                JsonElement id = data.get( "id" );
                JsonElement msg = data.get( "msg" );
                int msgIdentifier = data.get("ctr").getAsInt();
                if (id == null || msg == null) {
                    System.err.print ( "Badly formated \"recv\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                if(authID != id.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                
                int fromId = id.getAsInt();

                if (registry.userExists( fromId ) == false) {
                    System.err.print ( "Unknown source id for \"recv\" request: " + data );
                    sendResult( null, "\"wrong parameters\"" );
                    return;
                }

                if (registry.messageExists( fromId, msg.getAsString() ) == false &&
                    registry.messageExists( fromId, "_" + msg.getAsString() ) == false) {
                    System.err.println ( "Unknown message for \"recv\" request: " + data );
                    sendResult( null, "\"wrong parameters\"" );
                    return;
                }

                // Read message

                String response = registry.recvMessage( fromId, msg.getAsString() );
                me = registry.findUserByID(Integer.parseInt(msg.getAsString().split("_")[0]));
                String cert = me.cert;
                sendResult( "\"result\":" + response +",\"cert\":\""+cert+"\",\"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }

            // RECEIPT
            if (cmd.getAsString().equals( "receipt" )) {
                JsonElement id = data.get( "id" );
                JsonElement msg = data.get( "msg" );
                JsonElement receipt = data.get( "receipt" );
                int msgIdentifier = data.get("ctr").getAsInt();
                
                if (id == null || msg == null || receipt == null) {
                    System.err.print ( "Badly formated \"receipt\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                if(authID != id.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                
                int fromId = id.getAsInt();
                String response = null;
                if (registry.messageWasRed( fromId, msg.getAsString() ) == false) {
                    System.err.println ( "Unknown, or not yet red, message for \"receipt\" request: " + data );
                    response = "denied";
                    response = Base64.getEncoder().encodeToString(EncryptAES(response));
                    sendResult("\"result\":\""+response+"\", \"ctr\":\""+msgIdentifier+"\"", null);
                    return;
                }
                
                // Store receipt
                registry.storeReceipt( fromId, msg.getAsString(), receipt.getAsString() );
                response = "accepted";
                response = Base64.getEncoder().encodeToString(EncryptAES(response));
                sendResult("\"result\":\""+response+"\", \"ctr\":\""+msgIdentifier+"\"", null);
                return;
            }

            // STATUS
            if (cmd.getAsString().equals( "status" )) {
                JsonElement id = data.get( "id" );
                JsonElement msg = data.get( "msg" );
                int msgIdentifier = data.get("ctr").getAsInt();
                
                if (id == null || msg == null) {
                    System.err.print ( "Badly formated \"status\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                if(authID != id.getAsInt()){
                    sendResult(null, "\"Bad Request - Wrong ID provided\"");
                    return;
                }
                
                int fromId = id.getAsInt();

                if (registry.copyExists( fromId, msg.getAsString() ) == false) {
                    System.err.print ( "Unknown message for \"status\" request: " + data );
                    sendResult( null, "\"wrong parameters\"" );
                    return;
                }
                
                // Get receipts
                String response = registry.getReceipts( fromId, msg.getAsString() );
                
                sendResult( "\"result\":" + response +",\"ctr\":\""+msgIdentifier+"\"", null );
                return;
            }

            // ASKPK - Get User PublicKey
            if (cmd.getAsString().equals( "askPK" )) {
                JsonElement id = data.get( "id" );
                
                if (id == null) {
                    System.err.print ( "No \"id\" field in \"askPK\" request: " + data );
                    sendResult( null, "\"wrong request format\"" );
                    return;
                }
                
                byte[] temp_id = Base64.getDecoder().decode(id.getAsString());
                byte[] serverHMAC = calculateHMAC(temp_id,clientAESKey);
                byte[] clientHMAC = Base64.getDecoder().decode(data.get("mac").getAsString());
                if (!Arrays.equals(serverHMAC, clientHMAC)){
                    System.err.println("[askPK] Message Compromised!");
                    sendResult( null, "\"message integrity compromised\"" );
                    return;
                }
                temp_id = DecryptAES(temp_id);
                data.remove("id");
                data.addProperty("id", new String(temp_id,StandardCharsets.UTF_8));
                id = data.get("id");

                String response = registry.getPKRSA(id.getAsInt());

                sendResult( "\"result\":\"" + response + "\"", null );
                return;
            }
            
            sendResult( null, "\"Unknown request\"" );
            return;
            
        }else{
            
            // Send Server PublicKey
            if(cmd.getAsString().equals( "askServerPK" )){
                String ass = Server.sign();
                sendResultInit("\"result\":\""+Base64.getEncoder().encodeToString(Server.getServerPubKey().getEncoded())+"\",\n \"ass\":\""+Base64.getEncoder().encodeToString(ass.getBytes())+"\"\n",null);
                return;
            }

            // Get user Private AES KEY
            if(cmd.getAsString().equals( "sendServerAES" )){
                JsonElement secretKey = data.get( "sk" );
                String clientAESKeyString = secretKey.getAsString();
                byte[] temp = Base64.getDecoder().decode(clientAESKeyString);
                try{
                    temp = Server.decryptAsym(temp);
                    clientAESKey = new SecretKeySpec(temp, 0, temp.length, "AES");
                }catch(Exception e){
                    System.out.println(e);
                }
                //System.out.println(clientAESKey);
                return;
            }
        }
        
        sendResult( null, "\"Unknown request\"" );
        return;
    }

    public byte[] EncryptAES(String msg){
        byte[] cipherText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, clientAESKey, ivspec);
            cipherText = c.doFinal(msg.getBytes());
        }catch(Exception e){
            System.out.println(e);
            }
        return cipherText;
    }

    public byte[] DecryptAES(byte[] msg){
        byte[] decipheredText = null;
        try{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, clientAESKey, ivspec);
            decipheredText = c.doFinal(msg);
        }catch(Exception e){
            System.out.println(e);
        }
        return decipheredText; 
    }
    
    // CALCULATE HMAC ----------------------------------------------------------
    public static byte[] calculateHMAC(byte[] original, SecretKey sk){
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
    
    public static String generateString() {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        return uuid;
    }
    
    public static byte[] encryptAsym(PublicKey publickey, String msg) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publickey);
        return cipher.doFinal(msg.getBytes());
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
    
    public void
    run () {
        while (true) {
            JsonObject cmd = readCommand();
            if (cmd == null) {
                try {
                    client.close();
                } catch (Exception e) {}
                return;
            }
            executeCommand ( cmd );
        }

    }

}

