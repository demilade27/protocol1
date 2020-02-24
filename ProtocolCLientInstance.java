import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import sun.security.krb5.internal.crypto.Des;

@SuppressWarnings("unused")
public class ProtocolCLientInstance implements Runnable{
	Socket myConnection;
	boolean debug = true;
	static Cipher decAEScipher;
	static Cipher encAEScipher;
	String hexKey;
	
	public ProtocolCLientInstance(Socket myConnection) {
	    this.myConnection=myConnection;
	  
	    //Set up the cipher object

	    
	}

	@Override
	public void run() {
	    OutputStream outStream;
	    InputStream inStream;
	    try {
		outStream = myConnection.getOutputStream();
		inStream = myConnection.getInputStream();
		
		// Protocol Step 1
		// We send the ascii for "Connect Protocol 1"
		String messageString="Connect Protocol 1";
		byte[] message1 = messageString.getBytes();
		outStream.write(message1);
		if (debug)System.out.println("i have sent it ");
		
		
		//receive nonce step 2
		byte[] encryptedServerNonce =new byte[32];
		inStream.read(encryptedServerNonce);
		if (debug) System.out.println("Recived server nonce  :"+byteArrayToHexString(encryptedServerNonce));
		
		
		//send nonce back (step 3)
		outStream.write(encryptedServerNonce);
		if(debug) System.out.println("i sent back the nonce :"+byteArrayToHexString(encryptedServerNonce));
		
		
		  //get encryption and decrytion
	    byte[] keyBytes = "0".getBytes();
	    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    Cipher decAEScipherSession = Cipher.getInstance("AES");			
	    decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);
	    Cipher encAEScipherSession = Cipher.getInstance("AES");			
	    encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	    if (debug) System.out.println("Session key :"+byteArrayToHexString(keyBytes));
		//recieve the session key (step 4)
		
		byte[] sessionkey =new byte[48];
		inStream.read(sessionkey);
		if (debug) System.out.println("Recived server sessionkey  :"+byteArrayToHexString(sessionkey));
		
		//send back same session key (step 5)
		outStream.write(sessionkey);
		if (debug) System.out.println("sending server sessionkey  :"+byteArrayToHexString(sessionkey));
		
		
		//recieve the token 
		byte[] message =new byte[41];
		inStream.read(message);
		decAEScipherSession.doFinal(message);
		if (debug) System.out.println(byteArrayToHexString(message));
		
		}
		
		
		
		
	    
	    catch (IOException e) {
			//Nothing we can do about this one
			if (debug) System.out.println("See that cable on the back of your computer? Stop pulling it out: "+e);
			return;
		    } catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	
		
		
	}



private static byte[] xorBytes (byte[] one, byte[] two) {
if (one.length!=two.length) {
    return null;
} else {
    byte[] result = new byte[one.length];
    for(int i=0;i<one.length;i++) {
	result[i] = (byte) (one[i]^two[i]);
    }
    return result;
}
}

private static String byteArrayToHexString(byte[] data) { 
StringBuffer buf = new StringBuffer();
for (int i = 0; i < data.length; i++) { 
    int halfbyte = (data[i] >>> 4) & 0x0F;
    int two_halfs = 0;
    do { 
	if ((0 <= halfbyte) && (halfbyte <= 9)) 
	    buf.append((char) ('0' + halfbyte));
	else 
	    buf.append((char) ('a' + (halfbyte - 10)));
	halfbyte = data[i] & 0x0F;
    } while(two_halfs++ < 1);
} 
return buf.toString();
} 

private static byte[] hexStringToByteArray(String s) {
int len = s.length();
byte[] data = new byte[len / 2];
for (int i = 0; i < len; i += 2) {
    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
			  + Character.digit(s.charAt(i+1), 16));
}
return data;
}
}
