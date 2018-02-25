import com.google.gson.*;
import java.security.cert.X509Certificate;

class UserDescription implements Comparable {

    int id;		            // id extracted from the CREATE command
    JsonElement description;        // JSON user's description
    String uuid;		    // User unique identifier (across sessions)
    String pk;                      // public key RSA of this user
    String cert;

    UserDescription ( int id, JsonElement description ) {
        this.id = id;
        this.description = description;
        uuid = description.getAsJsonObject().get( "uuid" ).getAsString();
        pk = description.getAsJsonObject().get( "pk" ).getAsString();
        cert = description.getAsJsonObject().get("cert").getAsString();
        description.getAsJsonObject().addProperty( "id", new Integer( id ) );
    }

    UserDescription ( int id ) {
        this.id = id;
    }
    
    public String getPublicKeyRSA () {
        return pk;
    }

    public int compareTo ( Object x ) {
        return ((UserDescription) x).id - id;
    }

}
