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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//'server'
public class Receiver {
	//Variables
	private static ServerSocket serverSocket;
	private static DataInputStream dataIn;
	private static DataOutputStream dataOut;
	private static SecretKey symmetricKey;
	
	//Main
	public static void main(String[] args) throws Exception{
		System.out.println("Receiver has started");
		serverSocket = new ServerSocket(1024);
		
		System.out.println("Waiting for sender...");
		Socket socket = serverSocket.accept();
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println("Sender connected with IP: " + socket.getInetAddress());
//		MessageListener listener = new MessageListener(socket);
//		listener.start();
		
		System.out.println("Waiting for public key from Sender...");
		String publicKeyString = dataIn.readUTF();
		PublicKey pubKey = stringToPublicKey(publicKeyString);
		System.out.println("Received public key from Sender.");
		
		symmetricKey = generateKey(); //symmetric key
		String symmetricKeyString = keyToString(symmetricKey);
		System.out.println("Symmetric key generated.");
		
		System.out.println("Encrypting symmetric key with the public key.");
		byte[] encryptedSymKeyString = encryptAsymmetric(pubKey, symmetricKeyString.getBytes());
		System.out.println("Sending encrypted symmetric key.");
		//System.out.println("TEST: encrypted symmetric key: "+new String(encryptedSymKeyString)); //testprint
		dataOut.writeInt(encryptedSymKeyString.length);
		dataOut.write(encryptedSymKeyString);
		
		String message = "";
		while(!message.equals("q")) {
			System.out.println("Waiting for encrypted messages...");
			int encrMsgLength = dataIn.readInt();
			byte[] encryptedMsg = new byte[encrMsgLength];
			System.out.println("Received message: decrypting message...");
			dataIn.readFully(encryptedMsg, 0, encrMsgLength);
			
			message = new String(decryptSymmetric(encryptedMsg, symmetricKey));
			System.out.println("Received message: "+message);
		}
	}
	
	//Methods
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
	
	public static byte[] decryptSymmetric(byte[] tmp, SecretKey encryptionKey) throws Exception {
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        SecretKeySpec spec = new SecretKeySpec(encryptionKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, spec, iv);

        //System.out.println(tmp.length);
        return cipher.doFinal(tmp);
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


