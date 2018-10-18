import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.MessageDigest;
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
		System.out.println("--------------------");
		System.out.println("Receiver has started");
		System.out.println("--------------------");
		serverSocket = new ServerSocket(1024);
		
		System.out.println(System.currentTimeMillis()+":  Waiting for sender to connect...");
		Socket socket = serverSocket.accept();
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println(System.currentTimeMillis()+":  Sender connected with IP: " + socket.getInetAddress());
//		MessageListener listener = new MessageListener(socket);
//		listener.start();
		
		System.out.println(System.currentTimeMillis()+":  Waiting for public key from Sender...");
		String publicKeyString = dataIn.readUTF();
		PublicKey pubKey = stringToPublicKey(publicKeyString);
		System.out.println(System.currentTimeMillis()+":  Received public key from Sender.");
		
		symmetricKey = generateKey(); //symmetric key
		String symmetricKeyString = keyToString(symmetricKey);
		System.out.println(System.currentTimeMillis()+":  Symmetric key generated.");
		
		System.out.println(System.currentTimeMillis()+":  Encrypting symmetric key with the public key.");
		byte[] encryptedSymKeyString = encryptAsymmetric(pubKey, symmetricKeyString.getBytes());
		System.out.println(System.currentTimeMillis()+":  Sending encrypted symmetric key.\n");
		//System.out.println("TEST: encrypted symmetric key: "+new String(encryptedSymKeyString)); //testprint
		dataOut.writeInt(encryptedSymKeyString.length);
		dataOut.write(encryptedSymKeyString);
		
		String message = "";
		while(!message.equals("q")) {
			//Send nonce
			System.out.println(System.currentTimeMillis()+":  Sending nonce...");
			String nonce = generateNonce();
			System.out.println(System.currentTimeMillis()+":  Generated nonce: " + nonce);
			byte[] encrNonce = encryptSymmetric(nonce.getBytes(), symmetricKey);
			dataOut.writeInt(encrNonce.length);
			dataOut.write(encrNonce);
			
			System.out.println(System.currentTimeMillis()+":  Waiting for encrypted messages...");
			int encrMsgLength = dataIn.readInt();
			byte[] encryptedMsg = new byte[encrMsgLength];
			System.out.println(System.currentTimeMillis()+":  Received message: decrypting message...");
			dataIn.readFully(encryptedMsg, 0, encrMsgLength);
			
			int hashLength = dataIn.readInt();
			byte[] encrHash = new byte[hashLength];
			dataIn.readFully(encrHash, 0, hashLength);
			
			message = new String(decryptSymmetric(encryptedMsg, symmetricKey));
			byte[] hash = decryptSymmetric(encrHash, symmetricKey);
			
			if(!doesMesageMatchHash(message, new String(hash))) {
				System.out.println(System.currentTimeMillis()+":  Hash mismatch. Potential message modification detected.");
			}
			else {
				System.out.println(System.currentTimeMillis()+":  Hash matched, checking nonce.");
				String receivedNonce = message.substring(0, 8);
				message = message.substring(8);
				System.out.println(System.currentTimeMillis()+":  Received nonce: "+receivedNonce);
				if(receivedNonce.equals(nonce)) {
					System.out.println(System.currentTimeMillis()+":  Nonces verified.");
					System.out.println(System.currentTimeMillis()+":  Received message: "+message);
					System.out.println("------------------------------------------------\n");
				}
				else {
					System.out.println(System.currentTimeMillis()+":  Replay attack detected! Message ignored.");
				}
			}
		}
		System.out.println(System.currentTimeMillis()+":  Quit request, terminating.");
	}
	
	//Methods
	public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
	
	public static byte[] encryptSymmetric(byte[] data, SecretKey encryptionKey) throws Exception {
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        byte[] encryptData = cipher.doFinal(data);

        return encryptData;
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
	
	public static String generateNonce() {
		String nonce = "";
		for(int i=0; i<8; i++) {
			String num = ""+((int)(Math.random()*10));
			nonce += num;
		}
		return nonce;
	}
	
	public static byte[] generateHash(String mesage) throws Exception{
        MessageDigest md;
        md = MessageDigest.getInstance("MD5");
        byte[] thehashedMesage = md.digest(mesage.getBytes());
        return thehashedMesage;
    }
	
	public static boolean doesMesageMatchHash(String mesage, String md5HashedString) throws Exception{
        return new String(generateHash(mesage)).equals(md5HashedString);
    }
}


