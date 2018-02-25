import java.net.Socket;
import java.net.InetAddress;

class Client {
  
    public static void main(String[] args) {
        /** Define a host server */
        String host = "localhost";
        /** Define a port */
        int port = 8080;
        System.out.println("SocketClient initialized");

        try {
            /** Obtain an address object of the server */
            InetAddress address = InetAddress.getByName(host);
            /** Establish a socket connetion */
            Socket connection = new Socket(address, port);
            ClientActions client = new ClientActions(connection);

            new Thread(client).start();

            /** Close the socket connection. */
        }catch (Exception g) { 
            System.out.println("Exception: " + g); 
            System.exit(0);
        }
    }
    
}
