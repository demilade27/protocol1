import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Protocol2Attack {
	static int portNo = 11338;
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");


	    
		public static void main(String []args) throws IOException, ClassNotFoundException, InterruptedException {
			try { 
			
				
				Socket Socket = new Socket("127.0.0.1",portNo);
				ProtocolCLientInstance instance =new ProtocolCLientInstance(Socket);
				instance.run();
			
				
			} catch (Exception e) {
			    System.out.println("error in client "+e);
			}
		
			
		}

public static class ProtocolCLientInstance  {
	Socket socket;
	boolean debug = true;
	Cipher decAESsessionCipher;
	Cipher encAESsessionCipher;
	
	// i made two constructors because i want a way to know which one is just retrieving the encrypted key 
	//the idea i currenly have is tahat the one without the  extra i is gonna be used to just get a key  
	public ProtocolCLientInstance(Socket socket) {
		this.socket=socket;
	}
	
	//this one will take in the encrypted nonce+1 and it will run normally
	public void run() {
		 DataOutputStream outStream;
		    DataInputStream inStream;
		    try {
			outStream = new DataOutputStream(socket.getOutputStream());
			inStream = new DataInputStream(socket.getInputStream());
			try {
			    // Use crypto API to calculate y & g^y
			    DHParameterSpec dhSpec = new DHParameterSpec(p,g);
			    KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
			    diffieHellmanGen.initialize(dhSpec);
			    KeyPair serverPair = diffieHellmanGen.generateKeyPair();
			    PrivateKey y = serverPair.getPrivate();
			    PublicKey gToTheY = serverPair.getPublic();
			    
			    //Protocol message 1
			    outStream.writeInt(gToTheY.getEncoded().length);
			    outStream.write(gToTheY.getEncoded());

			    
			    //Protocol message 2
			    //PublicKey cert can vary in length, therefore the length is sent first
			    int publicKeyLen = inStream.readInt();
			    byte[] message1 = new byte[publicKeyLen];
			    inStream.read(message1);
			    KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
			    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
			    PublicKey gToTheX = keyfactoryDH.generatePublic(x509Spec);
	

			    
			    //Calculate session key
			    // This method sets decAESsessionCipher & encAESsessionCipher
			    calculateSessionKey(y, gToTheX);
			    
			    
			    
			    //send the encrypted nonce to the server 3 	
			    SecureRandom gene = new SecureRandom();
			    int clientNonce = gene.nextInt();
			    byte[] ClientNonceBytes = BigInteger.valueOf(clientNonce).toByteArray();
			    byte[]  encryptedClientNonce= encAESsessionCipher.doFinal(ClientNonceBytes);
			    outStream.write(encryptedClientNonce);
			    if (debug) System.out.println( "1 send nonce to server"+encryptedClientNonce);
			    
			    
//			    Protocol Step 4
			    byte[] message5ct = new byte[32];
			    inStream.read(message5ct);
			    byte[] decryptedServerNonce= decAESsessionCipher.doFinal(message5ct);
			    if (debug) System.out.println("2 server sent me this "+decryptedServerNonce);
			    byte[] serverNonce= new byte[4];
			    System.arraycopy(decryptedServerNonce, 16, serverNonce, 0, 4);
			    if (debug) System.out.println("3 i sent this to client 2"+serverNonce);
//
//			   
				//send the server the encrypted server nonce 5
			    Socket Socket = new Socket("127.0.0.1",portNo);
			    ProtocolCLientInstance2 hacker =new ProtocolCLientInstance2(Socket,serverNonce); 
			    hacker.run();
		

				
				
				
				//send the server the encrypted server nonce from (client 2) 6 
				byte [] encryptedServer  = hacker.getClientEncKey();
				byte[]  encryptedServerNonce= encAESsessionCipher.doFinal(encryptedServer);
				outStream.write(encryptedServerNonce);
			    if (debug) System.out.println("8 i recieved this from client 2"+encryptedServer);

			    if (debug) System.out.println("9 i sent this to the server"+encryptedServerNonce);

				
				
				
				//recieve key
				byte [] finaltoken= new byte[inStream.available()];
				inStream.read(finaltoken);
				byte[]  finaltokendec =decAESsessionCipher.doFinal(finaltoken);
				if (debug) System.out.println("10 final step"+new String(finaltokendec));
				
			    
			    

		    
			}
			catch (IllegalBlockSizeException e) {
			    outStream.write("Bad block size".getBytes());
			    if (debug) System.out.println("Doh "+e);
			    socket.close();
			    return;
			} catch (BadPaddingException e) {
			    outStream.write("Bad padding".getBytes());
			    socket.close();
			    if (debug) System.out.println("Doh "+e);
			    return;
			} catch (InvalidKeySpecException e) {
			    outStream.write("Bad certificate for PublicKey (g^x)".getBytes());
			    socket.close();
			    if (debug) System.out.println("Doh "+e);
			    return;
			} catch (NoSuchAlgorithmException e) {
			    System.out.println(e);// Not going to happen, AES hard wired
			} catch (InvalidAlgorithmParameterException e) {
			    System.out.println(e);// Not going to happen, DH Spec hard wired
			    e.printStackTrace();
			} 
			
		    } catch (IOException e) {
			//Nothing we can do about this one
			if (debug) System.out.println("Your wi-fi sucks: "+e);
			return;
		    }
		    }
	


	
	@SuppressWarnings("unused")
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException {
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");   
	    paramGen.init(1024);   
	    //Generate the parameters   
	    AlgorithmParameters params = paramGen.generateParameters();   
	    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);   
	
	    
	}
	private void calculateSessionKey(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		// Set up Cipher Objects
		decAESsessionCipher = Cipher.getInstance("AES");
		decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher = Cipher.getInstance("AES");
		encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
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
public static class ProtocolCLientInstance2 {
	Socket socket;
	boolean debug = true;
	int i ; 
	boolean hacking;
	byte[] serverNonce = new byte[4];
	static Cipher decAESsessionCipher;
	static Cipher encAESsessionCipher;
	public byte[] clientNonceKey;
	
	// i made two constructors because i want a way to know which one is just retrieving the encrypted key 
	//the idea i currenly have is tahat the one without the  extra i is gonna be used to just get a key  
	public ProtocolCLientInstance2(Socket socket) {
		this.socket=socket;
		hacking = false;
	}
	
	//this one will take in the encrypted nonce+1 and it will run normally
	public ProtocolCLientInstance2(Socket socket,byte[] serverNonce) {
		this.socket=socket;
		hacking=true;
		this.serverNonce=serverNonce;

	}


	public void run() {
		 DataOutputStream outStream;
		    DataInputStream inStream;
		    try {
			outStream = new DataOutputStream(socket.getOutputStream());
			inStream = new DataInputStream(socket.getInputStream());
			try {
			    // Use crypto API to calculate y & g^y
			    DHParameterSpec dhSpec = new DHParameterSpec(p,g);
			    KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
			    diffieHellmanGen.initialize(dhSpec);
			    KeyPair serverPair = diffieHellmanGen.generateKeyPair();
			    PrivateKey y = serverPair.getPrivate();
			    PublicKey gToTheY = serverPair.getPublic();
			    
			    //Protocol message 1
			    outStream.writeInt(gToTheY.getEncoded().length);
			    outStream.write(gToTheY.getEncoded());

			    
			    //Protocol message 2
			    //PublicKey cert can vary in length, therefore the length is sent first
			    int publicKeyLen = inStream.readInt();
			    byte[] message1 = new byte[publicKeyLen];
			    inStream.read(message1);
			    KeyFactory keyfactoryDH = KeyFactory.getInstance("DH");
			    X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message1);
			    PublicKey gToTheX = keyfactoryDH.generatePublic(x509Spec);
	
			    
			    //Calculate session key
			    calculateSessionKey(y, gToTheX);
			    
			    
			    if (debug) System.out.println("4 i got this from client 1"+serverNonce);

			    //send the encrypted nonce to the server (protocol 3)
			    byte[]  encryptedClientNonce= encAESsessionCipher.doFinal(serverNonce);
			    outStream.write(encryptedClientNonce);
			    if (debug) System.out.println("5 i sent this to get key encrytion "+encryptedClientNonce);
			    
			    
//			    Protocol Step 4
			    byte[] message5ct = new byte[32];
			    inStream.read(message5ct);
			    byte[]  deccryptedServerNonce=decAESsessionCipher.doFinal(message5ct);
			    clientNonceKey= new byte[16];
			    System.arraycopy(deccryptedServerNonce,0,clientNonceKey,0, 16);
			    if (debug) System.out.println("6 i client2 got this from server "+deccryptedServerNonce);
			    if (debug) System.out.println("7 this is what i will send to the client1"+clientNonceKey);
			    socket.close();

			}
			catch (IllegalBlockSizeException e) {
			    outStream.write("Bad block size".getBytes());
			    if (debug) System.out.println("Doh "+e);
			    socket.close();
			    return;
			} catch (BadPaddingException e) {
			    outStream.write("Bad padding".getBytes());
			    socket.close();
			    if (debug) System.out.println("Doh "+e);
			    return;
			} catch (InvalidKeySpecException e) {
			    outStream.write("Bad certificate for PublicKey (g^x)".getBytes());
			    socket.close();
			    if (debug) System.out.println("Doh "+e);
			    return;
			} catch (NoSuchAlgorithmException e) {
			    System.out.println(e);// Not going to happen, AES hard wired
			} catch (InvalidAlgorithmParameterException e) {
			    System.out.println(e);// Not going to happen, DH Spec hard wired
			    e.printStackTrace();
			} 
			
		    } catch (IOException e) {
			//Nothing we can do about this one
			if (debug) System.out.println("Your wi-fi sucks: "+e);
			return;
		    }
		    }
	public  byte[] getClientEncKey() {
		return clientNonceKey;
		
		
	}
	


	
	@SuppressWarnings("unused")
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException {
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");   
	    paramGen.init(1024);   
	    //Generate the parameters   
	    AlgorithmParameters params = paramGen.generateParameters();   
	    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);   

	    
	}
	private void calculateSessionKey(PrivateKey y, PublicKey gToTheX)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(y);
		serverKeyAgree.doPhase(gToTheX, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		// Set up Cipher Objects
		decAESsessionCipher = Cipher.getInstance("AES");
		decAESsessionCipher.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encAESsessionCipher = Cipher.getInstance("AES");
		encAESsessionCipher.init(Cipher.ENCRYPT_MODE, aesSessionKey);
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
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



