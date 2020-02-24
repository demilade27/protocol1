import java.net.Socket;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class ProtocolCLientInstance implements Runnable{
	Socket myConnection;
	boolean debug = true;
	static Cipher decAEScipher;
	static Cipher encAEScipher;
	String hexKey;
	
	public ProtocolCLientInstance(Socket myConnection,String hexKey) {
	    this.myConnection = myConnection;
	    //Set up the cipher object
	    this.hexKey=hexKey;
	    Key aesKey = new SecretKeySpec(hexStringToByteArray(hexKey), "AES");
	    try {
		decAEScipher = Cipher.getInstance("AES");
		decAEScipher.init(Cipher.DECRYPT_MODE, aesKey);
		encAEScipher = Cipher.getInstance("AES");
		encAEScipher.init(Cipher.ENCRYPT_MODE, aesKey);
	    } catch (Exception e) {
		System.out.println("Doh "+e);
	    }			
	}

	@Override
	public void run() {
	
		
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
