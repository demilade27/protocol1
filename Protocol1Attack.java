import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;





public class Protocol1Attack{
	
    static int portNo = 11337;
	

    
	public static void main(String []args) throws IOException, ClassNotFoundException, InterruptedException {
		try { 
		
			
			Socket Socket = new Socket("127.0.0.1",portNo);
			Thread instance = new Thread(new ProtocolCLientInstance(Socket));
			instance.start();
		
			
		} catch (Exception e) {
		    System.out.println("error in client "+e);
		}
		
	}
	

	

	
	private static class ProtocolCLientInstance implements Runnable{
		Socket myConnection;
		boolean debug = true;
	
		
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
		    
		    byte[] keyBytes = new byte[16];
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
			byte[] message =new byte[inStream.available()];
			
			inStream.read(message);
			byte[]decrytedMessage= decAEScipherSession.doFinal(message);
			if (debug) System.out.println(new String(decrytedMessage));
		
			
			}
			
			
			
			
		    
		    catch (IOException e) {
				//Nothing we can do about this one
				if (debug) System.out.println("See that cable on the back of your computer? Stop pulling it out: "+e);
				return;
			    } catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace();
				}
		
			
			
		}



	

	private String byteArrayToHexString(byte[] data) { 
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

	
	}

	
}

