import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketImpl;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;




@SuppressWarnings("unused")
public class Protocol1Client{
	static String hexKey;
    static int portNo = 11337;
	

    
	public static void main(String []args) throws UnknownHostException, IOException, ClassNotFoundException, InterruptedException {
		try { 
			while (true) {
			InetAddress host = InetAddress.getLocalHost();
			Socket Socket = new Socket(host.getHostName(),portNo);
			Thread instance = new Thread(new ProtocolCLientInstance(Socket,hexKey));
			instance.start();
			}
		} catch (Exception e) {
		    System.out.println("Doh "+e);
		}
		
	}
	
}
