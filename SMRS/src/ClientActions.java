import java.net.Socket;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import com.google.gson.stream.*;
import com.sun.deploy.uitoolkit.impl.fx.ui.CertificateDialog;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.ThreadLocalRandom;

class ClientActions implements Runnable {

    Scanner inCmd = new Scanner(System.in);
    Socket client;
    static JsonReader in;
    OutputStream out;
    String msg;
    String userID;
    String command;
    ClientSecurity clientSecurity;
    final String keysPath = "keys";
    int msgIdentifier = 0;
    X509Certificate cert = null;
    
    boolean init = true;
    ClientActions ( Socket c ) {
        client = c;
        
        try {
            in = new JsonReader( new InputStreamReader ( c.getInputStream(), "UTF-8") );
            out = c.getOutputStream();
            clientSecurity = new ClientSecurity();
        } catch (Exception e) {
            System.err.print( "Cannot use client socket: " + e );
            Thread.currentThread().interrupt();
            System.exit(1);
        }
    }

    public void run () {
        while (true) {
                
            if(init){
                PublicKey serverKey = getServerRSAPubKey();
                sendAESServer(serverKey);
                init = false;
            }
            
            /* prints menu and reads input command */
            command = printMenu();

            if ( command.equals("9") || command.equalsIgnoreCase("EXIT") ) {
                System.out.println("Exiting...");
                try {
                    client.close();
                } catch (Exception e) {}
                return;
            }
            
            executeCommand(command);
            JsonObject cmd = readCommand();
            while(cmd == null)
                cmd = readCommand();
            
            /* Tratamento da nova mensagem JSON */
            JsonElement json = cmd.get("json");
            /* A Verificar Integridade e Autenticidade da mensagem - HMAC-SHA1 (Encrypt-then-MAC -> Antes de desincriptar) */
            /* JsonElement para byte[] */
            byte[] tmp_json = Base64.getDecoder().decode(json.getAsString());
            /* Calcular HMAC aqui no cliente da mensagem encriptada e com a chave privada*/
            byte[] cHMAC_json = clientSecurity.calculateHMAC(tmp_json,clientSecurity.getKeyAES());
            /* Obter o HMAC que o server manda na mesagem encriptada */
            byte[] sHMAC_json = Base64.getDecoder().decode(cmd.get("hmac").getAsString());
            /* Comparar os dois HMAC a ver se são iguais, caso sejam diferentes a mensagem foi comprometida */
            if (!Arrays.equals(cHMAC_json, sHMAC_json)){
                System.err.println("Message Compromised!");
                // sendResult( null, "\"message integrity compromised\"" );
                return;
            }
            /* Passagem de 2Json para Json original */
            byte[] tmp_newMsgJson = Base64.getDecoder().decode(json.getAsString());
            String msgJson = new String(clientSecurity.DecryptAES(tmp_newMsgJson),StandardCharsets.UTF_8);
            cmd = new JsonParser().parse(msgJson).getAsJsonObject();
            /* */

            if(cmd.get("error") != null){
                //System.out.println("ERROR ALERT: Action Discarded!");
                System.err.println(cmd.get("error").getAsString());
                continue;
            }
            parseCommand(command,cmd);
        }
    }
    
    String printMenu(){
        System.out.println("");
        System.out.println("* * * * * * * * * * * * MENU * * * * * * * * * * * *");
        System.out.println("1 - CREATE    2 - LIST    3 - NEW        4 - ALL");
        System.out.println("5 - SEND      6 - RECV    7 - RECEIPT    8 - STATUS");
        System.out.println("9 - EXIT");
        System.out.println("Input an action from the menu to continue...");
        System.out.print(" > ");
        command = inCmd.next();
        inCmd.nextLine();
        while(!command.equals("1") && !command.equals("2") && !command.equals("3") && !command.equals("4") && !command.equals("5") && !command.equals("6") && !command.equals("7") 
                && !command.equals("8") && !command.equals("9") && !command.equalsIgnoreCase("create") && !command.equalsIgnoreCase("list") 
                && !command.equalsIgnoreCase("new") && !command.equalsIgnoreCase("all") && !command.equalsIgnoreCase("send") && !command.equalsIgnoreCase("recv") 
                && !command.equalsIgnoreCase("receipt") && !command.equalsIgnoreCase("status") && !command.equalsIgnoreCase("exit")){
            System.out.println("\nWrong command!\n");
            System.out.println("* * * * * * * * * * * * MENU * * * * * * * * * * * *");
            System.out.println("1 - CREATE    2 - LIST    3 - NEW        4 - ALL");
            System.out.println("5 - SEND      6 - RECV    7 - RECEIPT    8 - STATUS");
            System.out.println("9 - EXIT");
            System.out.println("Input an action from the menu to continue...");
            System.out.print(" > ");
            command = inCmd.next();
            inCmd.nextLine();
        }
        return command;
    }

    void executeCommand ( String command ) {
        try{
            // CREATE
            if ( command.equals("1") || command.equalsIgnoreCase("CREATE") ) {
                String flag = "false";
                //byte[] id = clientSecurity.generateHashCC();
                String id_manual;
                PublicKey pubKey = clientSecurity.generateAsymKey();
                //if(id == null){
                    System.out.print("Insert ID: ");
                    id_manual = inCmd.next();
                    byte[] id = id_manual.getBytes();
                    inCmd.nextLine();
                    flag = "true";
                    File keysDir = new File(keysPath+"/"+id_manual);
                    if (keysDir.exists() == false){
                        String test = "{\"privKey\": \""+Base64.getEncoder().encodeToString(clientSecurity.getPrivateKey().getEncoded())+"\", \n \"pubKey\":\""+Base64.getEncoder().encodeToString(pubKey.getEncoded())+"\" \n }";
                        saveOnFile(keysPath+"/"+id_manual,test);
                    }else{
                        JsonObject in = new JsonParser().parse(readFromFile(keysPath+"/"+id_manual)).getAsJsonObject();
                        byte[] keyBytes = Base64.getDecoder().decode(in.get("pubKey").getAsString());
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        clientSecurity.setPubKey(kf.generatePublic(spec));
                        pubKey = kf.generatePublic(spec);
                        byte[] keyBytesPriv = Base64.getDecoder().decode(in.get("privKey").getAsString());
                        PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(keyBytesPriv);
                        kf = KeyFactory.getInstance("RSA");
                        clientSecurity.setPrivateKey(kf.generatePrivate(spec2)); 
                    }
                    cert = clientSecurity.getCertificate();
                //}
                String type = "create";
                setMsgID();
                if(cert != null)
                    msg = "{\n \"type\": \""+type+"\",\n \"uuid\": \""+Base64.getEncoder().encodeToString(id)+"\",\n \"pk\": \""+Base64.getEncoder().encodeToString(pubKey.getEncoded())+"\",\n \"cc\":\""+flag+"\",\n \"cert\":\""+Base64.getEncoder().encodeToString(cert.getEncoded())+"\",\n \"ctr\":\""+msgIdentifier+"\"\n}";
                else
                    msg = "{\n \"type\": \""+type+"\",\n \"uuid\": \""+Base64.getEncoder().encodeToString(id)+"\",\n \"pk\": \""+Base64.getEncoder().encodeToString(pubKey.getEncoded())+"\",\n \"cc\":\""+flag+"\",\n \"cert\":\""+Base64.getEncoder().encodeToString("".getBytes())+"\",\n \"ctr\":\""+msgIdentifier+"\"\n}";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg); // encrypt original JSON message
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES()); // calculate hmac for original encrypted JSON
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }"; // create new JSON message
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 )); // send new JSON message
                return;
            }
            
            // LIST
            if ( command.equals("2") || command.equalsIgnoreCase("LIST") ) {
                System.out.print("Insert ID [or \"all\"] to list: ");
                String id = inCmd.next();
                inCmd.nextLine();
                String type = "list";
                setMsgID();
                if(id.equals("all")){
                    msg = "{\n \"type\": \""+type+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                }else{
                    msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+id+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                }
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }

            // NEW
            if ( command.equals("3") || command.equalsIgnoreCase("NEW") ) {
                String type = "new";
                setMsgID();
                msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+userID+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }

            // ALL
            if ( command.equals("4") || command.equalsIgnoreCase("ALL") ) {
                String type = "all";
                setMsgID();
                msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+userID+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }

            // SEND
            if ( command.equals("5") || command.equalsIgnoreCase("SEND") ) {
                boolean ex = true;
                while(ex){
                    try{
                        System.out.print("Insert ID of recipient: ");
                        String id = inCmd.nextLine();
                        Integer.parseInt(id);
                        byte[] tmp_dst = clientSecurity.EncryptAES(id);
                        PublicKey pubKey = getRSAPubKey(tmp_dst);
                        System.out.print("Insert message: ");
                        String msgString = inCmd.nextLine();
                        String type = "send";
                        /* Sign Message */
                        String signed = clientSecurity.sign(msgString);
                        /* Hybrid Cryptosystem */
                        SecretKey hyb_sk = clientSecurity.createKeyAES_hybMSG(); /* create new Secret key for this message */
                        byte[] hyb_msg = clientSecurity.EncryptAES(hyb_sk, msgString); /* encrypt msg with Secret key */
                        String hyb_sk_msg = Base64.getEncoder().encodeToString(clientSecurity.encryptAsym(pubKey,hyb_sk.getEncoded())); /* encrypt Secret key with RSA from dst */
                        String hyb_sk_copy = Base64.getEncoder().encodeToString(clientSecurity.encryptAsym(clientSecurity.getPubKey(),hyb_sk.getEncoded())); /* encrypt Secret key with RSA from src for copy */
                        msgString = Base64.getEncoder().encodeToString(hyb_msg);
                        String msgCopy = "{\n \"type\": \"msgCopy\",\n \"msg\": \""+msgString+"\",\n \"key\": \""+hyb_sk_copy+"\"\n }"; /* para no receipt ficar guardada a msg e a chave para a decifrar */
                        msgCopy = Base64.getEncoder().encodeToString(msgCopy.getBytes()); /* To avoid error in status read (receipt treatment error) */
                        /* */
                        setMsgID();
                        msg = "{\n \"type\": \""+type+"\",\n \"src\": \""+userID+"\",\n \"dst\": \""+id+"\",\n \"msg\": \""+msgString+"\",\n \"copy\": \""+msgCopy+"\",\n \"sign\": \""+signed+"\",\n \"key\": \""+hyb_sk_msg+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";

                        /* Stuff para 2 msg json */
                        byte[] newMSG = clientSecurity.EncryptAES(msg);
                        byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                        String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                        out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                        ex = false;
                    }catch(Exception e){
                        System.err.println(e);
                        System.out.println("Parameters wrong, please try again.");
                        ex = true;
                    }
                }
                return;
            }

            // RECV
            if ( command.equals("6") || command.equalsIgnoreCase("RECV") ) {
                System.out.print("Insert ID of message [ senderID_msgID ]: ");
                String msgID = inCmd.next();
                inCmd.nextLine();
                String type = "recv";
                setMsgID();
                msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+userID+"\",\n \"msg\": \""+msgID+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }

            // RECEIPT
            if ( command.equals("7") || command.equalsIgnoreCase("RECEIPT") ) {
                System.out.println("Current userID of Message box: "+userID);
                System.out.print("Insert msgID of message to confirm reception [ senderID_msgID ]: ");
                String msgID = inCmd.next();
                inCmd.nextLine();
                String type = "receipt";
                String sign = ""+userID+msgID+msgIdentifier+"";
                byte[] tmp_sign = clientSecurity.encryptAsymPrivKey(sign);
                sign = Base64.getEncoder().encodeToString(tmp_sign);
                setMsgID();
                msg = "{\n\"type\": \""+type+"\",\n\"id\": \""+userID+"\",\n\"msg\": \""+msgID+"\",\n\"receipt\": \""+sign+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }

            // STATUS
            if ( command.equals("8") || command.equalsIgnoreCase("STATUS") ) {
                System.out.println("current userID of Receipt box: " + userID);
                System.out.print("Insert sent msgID (receiverID_msgID): ");
                String msgID = inCmd.next();
                inCmd.nextLine();
                String type = "status";
                setMsgID();
                msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+userID+"\",\n \"msg\": \""+msgID+"\",\n \"ctr\":\""+msgIdentifier+"\"\n }";
                /* Stuff para 2 msg json */
                byte[] newMSG = clientSecurity.EncryptAES(msg);
                byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                return;
            }
        }catch(Exception e){
            System.out.println(e);
            System.exit(2);
        }
        return;
    }
    
    JsonObject readCommand () {
        try {
            JsonElement data = new JsonParser().parse( in );
            if (data.isJsonObject()) {
                return data.getAsJsonObject();
            }
            System.err.print ( "Error while reading command from socket (not a JSON object), connection will be shutdown\n" );
            return null;
        } catch (Exception e) {
            System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
            System.exit(3);
            return null;
        }
    }
    
    void parseCommand(String command, JsonObject cmd)
    {
        // CREATE
        if(command.equals("1") || command.equalsIgnoreCase("CREATE")){
            String result = cmd.getAsJsonObject().get( "result" ).getAsString();
            int receivedMsgIdentifier = cmd.getAsJsonObject().get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("Create Message - WRONG IDENTIFIER!");
                return;
            }
            if(result.equals("authChallenge")){
                String message = cmd.getAsJsonObject().get("msg").getAsString();
                try{
                    message = new String(clientSecurity.decryptAsym(Base64.getDecoder().decode(message)),StandardCharsets.UTF_8);
                    setMsgID();
                    msg = "{\n \"type\": \"authResponse\",\n \"msg\": \""+message+"\", \n \"ctr\":\""+msgIdentifier+"\"\n}";
                    /* Stuff para 2 msg json */
                    byte[] newMSG = clientSecurity.EncryptAES(msg);
                    byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
                    String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
                    out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
                }catch(Exception e){
                    System.err.println(e);
                    return;
                }
                
                cmd = readCommand();
                while(cmd == null)
                    cmd = readCommand();
                
                JsonElement json = cmd.get("json");
                byte[] tmp_json = Base64.getDecoder().decode(json.getAsString());
                byte[] cHMAC_json = clientSecurity.calculateHMAC(tmp_json,clientSecurity.getKeyAES());
                byte[] sHMAC_json = Base64.getDecoder().decode(cmd.get("hmac").getAsString());
                if (!Arrays.equals(cHMAC_json, sHMAC_json)){
                    System.err.println("Message Compromised!");
                    return;
                }
                
                byte[] tmp_newMsgJson = Base64.getDecoder().decode(json.getAsString());
                String msgJson = new String(clientSecurity.DecryptAES(tmp_newMsgJson),StandardCharsets.UTF_8);
                System.out.println("Welcome Back!");
                cmd = new JsonParser().parse(msgJson).getAsJsonObject();
            
                receivedMsgIdentifier = cmd.getAsJsonObject().get("ctr").getAsInt();
                if(receivedMsgIdentifier != msgIdentifier){
                    System.err.println("Challenge Response - WRONG IDENTIFIER!");
                    return;
                }
                result = cmd.getAsJsonObject().get( "result" ).getAsString();
                userID = result;
                System.out.println("server ID: "+userID);
            }else{  
                userID = result;
                System.out.println("server ID: "+userID);
            }
        }
        
        // LIST
        else if(command.equals("2") || command.equalsIgnoreCase("LIST")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("LIST message - Wrong Identifier!");
                return;
            }
            JsonArray arr = cmd.getAsJsonArray("data");
            JsonObject temp;
            System.out.println("Clients found: "+arr.size()+"\n");
            for(int i = 0; i < arr.size(); i++){
            temp = arr.get(i).getAsJsonObject();
            String resultString1 = temp.get("uuid").getAsString();
            String resultString2 = temp.get("id").getAsString();
            System.out.println("Client "+(i+1)+": "+ " uuid: "+ resultString1 + " id: "+resultString2);
            }
        }
        
        // NEW
        else if(command.equals("3") || command.equalsIgnoreCase("NEW")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("NEW message - WRONG IDENTIFIER");
                return;
            }
            JsonArray arr = cmd.getAsJsonArray("result"); //{"result":["15_1"]}
            String src = null;
            String temp="",temp2="";
            boolean flag = false;
            for(int i = 0; i < arr.size(); i++){
                src = arr.get(i).getAsString();
                temp="";
                temp2="";
                flag = false;
                for(int j = 0; j < src.length(); j++){
                if(src.charAt(j) == '_'){
                    flag = true;
                    continue;
                }
                if(!flag)
                    temp += src.charAt(j);
                else
                    temp2 += src.charAt(j);
                }
            System.out.println("Unread Message received from user "+temp+" with message ID "+temp2);
            }
        }
        
        // ALL
        else if(command.equals("4") || command.equalsIgnoreCase("ALL")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("ALL message - WRONG IDENTIFIER");
                return;
            }
            JsonArray arr = cmd.getAsJsonArray("result"); //{"result":[["23_1"],["1_1"]]} |||| "result": [[<received messages' identifiers>][sent messages' identifiers]]
            String src = null;
            String temp="",temp2="";
            boolean flag = false, alreadyRead=false;
            //------------------------MENSAGENS RECEBIDAS ------------------------
            JsonArray received = arr.get(0).getAsJsonArray(); //Vai buscar primeira parte do array results
            System.out.println("--- Messages received ---\n");
            for(int i = 0; i < received.size(); i++){
                src = received.get(i).getAsString();
                temp="";
                temp2="";
                flag = false;
                alreadyRead = false;
                for(int j = 0; j < src.length(); j++){
                    if(src.charAt(0)== '_' && !alreadyRead){
                        alreadyRead = true;
                        continue;
                    }
                        
                    if(src.charAt(j) == '_'){
                        flag = true;
                        continue;
                    }
                    if(!flag)
                        temp += src.charAt(j);
                    else
                        temp2 += src.charAt(j);
                }
                if(alreadyRead)
                    System.out.println("Message received from user "+temp+" with message ID "+temp2);
                else
                    System.out.println("Unread Message received from user "+temp+" with message ID "+temp2);
            }
            //------------------------MENSAGENS ENVIADAS ------------------------
            JsonArray sent = arr.get(1).getAsJsonArray(); //Vai buscar segunda parte do array results
            System.out.println("\n--- Messages sent ---\n");
            for(int i = 0; i < sent.size(); i++){
                src = sent.get(i).getAsString();
                temp="";
                temp2="";
                flag = false;
                for(int j = 0; j < src.length(); j++){
                if(src.charAt(j) == '_'){
                    flag = true;
                    continue;
                }
                if(!flag)
                    temp += src.charAt(j);
                else
                    temp2 += src.charAt(j);
                }
            System.out.println("Message sent to user "+temp+" with message ID "+temp2);
            }
        }
        
        // SEND
        else if(command.equals("5") || command.equalsIgnoreCase("SEND")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("SEND message - WRONG IDENTIFIER");
                return;
            }
            JsonArray arr = cmd.getAsJsonArray("result"); //{"result":["7_3","1_3"]}
            String dst = arr.get(1).getAsString();
            String temp="",temp2="";
            boolean flag = false;
            for(int i = 0; i < dst.length(); i++){
                if(dst.charAt(i) == '_'){
                    flag = true;
                    continue;
                }
                if(!flag)
                    temp += dst.charAt(i);
                else
                    temp2 += dst.charAt(i);
            }
            System.out.println("Sent from user "+userID+" to user "+temp+" with message ID "+temp2);
        }
        
        // RECV
        else if ( command.equals("6") || command.equalsIgnoreCase("RECV") ) {
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("RECV message - WRONG IDENTIFIER");
                return;
            }
           try{
            byte[] ola = Base64.getDecoder().decode(cmd.get("cert").getAsString());
            String stringOla = new String(ola,StandardCharsets.UTF_8);
            if(!stringOla.equals("")){
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream inStream = new ByteArrayInputStream(ola);
            X509Certificate receivedCert = (X509Certificate) cf.generateCertificate(inStream);
            if(!clientSecurity.validateCertificates(receivedCert)){
                System.err.print ( "--- Invalid certificate: ---");
            }else{
                System.out.println("--- Valid Certificate ---");
            }
            }
            }catch(Exception e){e.printStackTrace();}
            
            JsonArray arr = cmd.getAsJsonArray("result");
            byte[] msgB = null;
            try{
                String src = arr.get(0).getAsString();
                String msg = arr.get(1).getAsString();
                String sign = arr.get(2).getAsString();
                String sk = arr.get(3).getAsString();
                
                byte[] srcB = clientSecurity.EncryptAES(src);
                PublicKey pk = getRSAPubKey(srcB);
                
                /* Hybrid Cryptosystem */
                try{
                    byte[] skB = clientSecurity.decryptAsym(Base64.getDecoder().decode(sk));
                    SecretKey skey = null;

                    skey = new SecretKeySpec(skB, 0, skB.length, "AES");

                    msgB = Base64.getDecoder().decode(msg);
                    msg = new String(clientSecurity.DecryptAES(skey,msgB), StandardCharsets.UTF_8);
                }catch(Exception e){
                    System.out.println(e);
                }
                
                if(clientSecurity.verify(pk,msg,sign)){
                    System.out.println("Message received: " + msg);
                }else{
                    System.out.println("Source Not Verified! Signature Not Valid!");
                }
            }catch(Exception e){
                System.out.println(e);
            }
        }
        
        // RECEIPT
        else if(command.equals("7") || command.equalsIgnoreCase("RECEIPT")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("RECEIPT message - WRONG IDENTIFIER");
                return;
            }
            String response = cmd.getAsJsonObject().get( "result" ).getAsString();
            response = new String(clientSecurity.DecryptAES(Base64.getDecoder().decode(response)),StandardCharsets.UTF_8);
            if(response.equals("denied"))
                System.err.println("ERROR: RECEIPT NOT VALID");
            return;
        }
        
        // STATUS
        else if(command.equals("8") || command.equalsIgnoreCase("STATUS")){
            int receivedMsgIdentifier = cmd.get("ctr").getAsInt();
            if(receivedMsgIdentifier != msgIdentifier){
                System.err.println("STATUS message - WRONG IDENTIFIER");
                return;
            }
            JsonObject res = cmd.getAsJsonObject("result");
            JsonElement copy = res.get("msg");
            String copyString = copy.getAsString();
            copyString = new String(Base64.getDecoder().decode(copyString), StandardCharsets.UTF_8);
            JsonObject data = new JsonParser().parse(copyString).getAsJsonObject(); /* copy é uma json por si com msg e key */
            JsonElement msgC = data.get("msg");
            String msgString = msgC.getAsString();
            JsonElement sk = data.get("key");
            
            try{
                /* Hybrid Cryptosystem */
                byte[] skB = clientSecurity.decryptAsym(Base64.getDecoder().decode(sk.getAsString()));
                SecretKey skey = null;
                skey = new SecretKeySpec(skB, 0, skB.length, "AES");
                byte[] msgB = null;
                msgB = Base64.getDecoder().decode(msgString);
                msgString = new String(clientSecurity.DecryptAES(skey,msgB), StandardCharsets.UTF_8);
            }catch(Exception e){
                System.out.println(e);
            }
            System.out.println("Message: " + msgString);
            
            JsonArray receipts = res.getAsJsonArray("receipts");
            for(int i = 0; i < receipts.size();i++){
                JsonObject obj = receipts.get(i).getAsJsonObject();
                String date = obj.get("date").getAsString();
                String id = obj.get("id").getAsString();
                String receipt = obj.get("receipt").getAsString();
                
                byte[] tmp_rec = Base64.getDecoder().decode(receipt);
                byte[] tmp_id = clientSecurity.EncryptAES(id);
                PublicKey tmp_pk = getRSAPubKey(tmp_id);
                byte[] tmp_receipt = null;
                try{
                    tmp_receipt = clientSecurity.decryptAsymPubKey(tmp_pk,tmp_rec);
                }catch(Exception e){
                    System.out.println("Data: "+date+"\nId: "+id+"\nReceipt: ERROR - Invalid Receipt \n");
                    return;
                }
                receipt = new String(tmp_receipt,StandardCharsets.UTF_8);
                System.out.println("Data: "+date+"\nId: "+id+"\nReceipt_"+receipt+": VALID\n");
            }     
        }
        
    }
    
    public PublicKey getRSAPubKey(byte[] id){
        PublicKey publicKey = null;
        try{
            String type = "askPK";
            byte[] mac = clientSecurity.calculateHMAC(id,clientSecurity.getKeyAES());
            msg = "{\n \"type\": \""+type+"\",\n \"id\": \""+Base64.getEncoder().encodeToString(id)+"\",\n \"mac\": \""+Base64.getEncoder().encodeToString(mac)+"\"\n }"; 
            /* Stuff para 2 msg json */
            byte[] newMSG = clientSecurity.EncryptAES(msg);
            byte[] mac_json = clientSecurity.calculateHMAC(newMSG,clientSecurity.getKeyAES());
            String newMsgJson = "{\n \"type\": \"msg\",\n \"json\": \""+Base64.getEncoder().encodeToString(newMSG)+"\",\n \"hmac\": \""+Base64.getEncoder().encodeToString(mac_json)+"\"\n }";
            out.write (newMsgJson.getBytes( StandardCharsets.UTF_8 ));
            
            JsonObject cmd = readCommand();
            while(cmd == null)
                cmd = readCommand();
            
            /* Tratamento da nova mensagem JSON */
            JsonElement json = cmd.get("json");
            byte[] tmp_json = Base64.getDecoder().decode(json.getAsString());
            byte[] cHMAC_json = clientSecurity.calculateHMAC(tmp_json,clientSecurity.getKeyAES());
            byte[] sHMAC_json = Base64.getDecoder().decode(cmd.get("hmac").getAsString());
            if (!Arrays.equals(cHMAC_json, sHMAC_json)){
                System.err.println("Message Compromised!");
            }
            
            byte[] tmp_newMsgJson = Base64.getDecoder().decode(json.getAsString());
            String msgJson = new String(clientSecurity.DecryptAES(tmp_newMsgJson),StandardCharsets.UTF_8);
            cmd = new JsonParser().parse(msgJson).getAsJsonObject();
            
            byte[] keyBytes = Base64.getDecoder().decode(cmd.get("result").getAsString());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(spec);
        }catch(Exception e){
            System.out.println("Error ocurred: "+e);
        }
        return publicKey;
    }
    
    public PublicKey getServerRSAPubKey(){
        PublicKey publicKey = null;
        try{
            msg = "{\n \"type\": \"askServerPK\"\n }"; 
            out.write (msg.getBytes( StandardCharsets.UTF_8 ));
            
            JsonObject cmd = readCommand();
            while(cmd == null)
                cmd = readCommand();
            
            byte[] keyBytes = Base64.getDecoder().decode(cmd.get("result").getAsString());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(spec);
            /* Verificacao da Chave do Servidor */
            String ass = new String(Base64.getDecoder().decode(cmd.get("ass").getAsString()), StandardCharsets.UTF_8);
            if(!clientSecurity.verify(publicKey, publicKey.toString(), ass)){
                System.err.println("Server Key not Verified!");
                return null;
            }
        }catch(Exception e){
            System.out.println("Error ocurred: "+e);
        }
        return publicKey;
    }
    
    public void sendAESServer(PublicKey serverKey){
        try{
            SecretKey sk = clientSecurity.createKeyAES();
            String skString = Base64.getEncoder().encodeToString(clientSecurity.encryptAsym(serverKey,sk.getEncoded()));
            msg = "{\n \"type\": \"sendServerAES\",\n \"sk\":\""+skString+"\"\n }"; 
            System.out.println("Secure Conection to Server Established");
            out.write (msg.getBytes( StandardCharsets.UTF_8 ));
        }catch(Exception e){
            System.out.println("Error ocurred: "+e);
        }
    }
    
    private static void
    saveOnFile ( String path, String data ) throws Exception {
        FileWriter f = new FileWriter( path );
        f.write( data );
        f.flush();
        f.close();
    }

    private static String
    readFromFile ( String path ) throws Exception {
        FileInputStream f = new FileInputStream( path );
        byte [] buffer = new byte[f.available()];
        f.read( buffer );
        f.close();

        return new String( buffer, StandardCharsets.UTF_8 );
    }
    
    private void setMsgID(){
        int randomNum = ThreadLocalRandom.current().nextInt(1, 5 + 1); //(min,max + 1) para ser inclusive
        if(msgIdentifier + randomNum > 50){
            msgIdentifier = 0 + randomNum;
        }else{
            msgIdentifier += randomNum;
        }
    }
}
