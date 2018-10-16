import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

//'server'
public class Receiver {
	private static ServerSocket serverSocket;
	private static DataInputStream dataIn;
	private static DataOutputStream dataOut;
	private static SecretKey symmetricKey;
	
	public static void main(String[] args) throws Exception{
		System.out.println("Server has started");
		serverSocket = new ServerSocket(1024);
		
		System.out.println("Waiting for sender...");
		Socket socket = serverSocket.accept();
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println("Sender connected.");
//		MessageListener listener = new MessageListener(socket);
//		listener.start();
		
		System.out.println("Starting generation of symmetric key.");
		symmetricKey = generateKey(); //symmetric key
		String symmetricKeyString = keyToString(symmetricKey);
		
		System.out.println("Waiting for public key to encrypt and send the symmetric key...");
		String publicKeyString = dataIn.readUTF();
		PublicKey pubKey = stringToPublicKey(publicKeyString);
		System.out.println("Received public key");
		
		System.out.println("Encrypting symmetric key with the public key.");
		byte[] encryptedSymKeyString = encryptAsymmetric(pubKey, symmetricKeyString.getBytes());
		System.out.println("Sending encrypted symmetric key.");
		//System.out.println("TEST: encrypted symmetric key: "+new String(encryptedSymKeyString)); //testprint
		dataOut.writeInt(encryptedSymKeyString.length);
		dataOut.write(encryptedSymKeyString);
		
		//otherstuff
	}
	
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
	
    public static byte[] encryptAsymmetric(/*byte[] publicKey,*/ PublicKey key, byte[] inputData) throws Exception {
		//PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));

	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.PUBLIC_KEY, key);
	
	    byte[] encryptedBytes = cipher.doFinal(inputData);
	
	    return encryptedBytes;
    }
    
    public static PublicKey stringToPublicKey(String key) throws Exception {
		byte[] stringBytes = Base64.getDecoder().decode(key);
		return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(stringBytes));
    }
	
	public static String keyToString(SecretKey secretKey) {
		return Base64.getEncoder().encodeToString(secretKey.getEncoded());
	}
}


