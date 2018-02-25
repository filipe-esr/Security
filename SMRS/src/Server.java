import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Cipher;

class Server {
    
    static PublicKey pubKey = null;
    static PrivateKey privKey = null;
    
    static public void
    waitForClients ( ServerSocket s ) {
        ServerControl registry = new ServerControl();

        try {
            while (true) {
                Socket c = s.accept();
                ServerActions handler = new ServerActions( c, registry );
                new Thread( handler ).start ();
            }
        } catch ( Exception e ) {
            System.err.print( "Cannot use socket: " + e );
        }

    }

    public static void main ( String[] args ) {
        if (args.length < 1) {
            System.err.print( "Usage: port\n" );
            System.exit( 1 );
        }

        int port = Integer.parseInt( args[0] );

        try {
            ServerSocket s = new ServerSocket( port, 5, InetAddress.getByName( "localhost" ) );
            System.out.print( "Started server on port " + port + "\n" );
            
            generateAsymKey();
            
            waitForClients( s );
        } catch (Exception e) {
            System.err.print( "Cannot open socket: " + e );
            System.exit( 1 );
        }

    }
    
    public static void generateAsymKey(){
        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            pubKey = keyPair.getPublic();
            privKey = keyPair.getPrivate();
        }catch(Exception e){
            System.out.println("Exception: " + e);
        }
    }
    
    public static byte[] decryptAsym(byte[] msgEncrypted) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        return cipher.doFinal(msgEncrypted);
    }
    
    public static PublicKey getServerPubKey(){
        return pubKey;
    }
    
    public static String sign() {
        String msg = pubKey.toString();
        byte[] signature = null;
        try{
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privKey);
            privateSignature.update(msg.getBytes(UTF_8));
            signature = privateSignature.sign();
        }catch(Exception e){
            System.err.println(e);
        }
        return Base64.getEncoder().encodeToString(signature);
    }
}
