import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//'terminal client'
public class Sender {
	//Variables
	private static Socket socket;
	private static DataInputStream dataIn;
	private static DataOutputStream dataOut;
	private static SecretKey symmetricKey;
	private static String message;
	
	public Sender() throws Exception{
		System.out.println("-------------------");
		System.out.println("Sender has started.");
		System.out.println("-------------------");
		System.out.println(System.currentTimeMillis()+":  Connecting to 0.0.0.0 port 1024");
		socket = new Socket("0.0.0.0", 1024);
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println(System.currentTimeMillis()+":  Connected to socket.");
		
		//Generating asymmetric keys
		System.out.println(System.currentTimeMillis()+":  Starting asymmetric encryption...");
		System.out.println(System.currentTimeMillis()+":  Generating public and private keys.");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512); //Number of bits in both keys
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();    //This is the public key
		PrivateKey privKey = keyPair.getPrivate(); //This is the private key
		
		System.out.println(System.currentTimeMillis()+":  Sending public key...");
		String publicKeyString = keyToString(pubKey);
		dataOut.writeUTF(publicKeyString);
		
		System.out.println(System.currentTimeMillis()+":  Waiting to receive encrypted symmetric key...");
		int encrSymKeyLength = dataIn.readInt();
		byte[] encryptedSymKeyString = new byte[encrSymKeyLength];
		dataIn.readFully(encryptedSymKeyString, 0, encrSymKeyLength);
		System.out.println(System.currentTimeMillis()+":  Encrypted symmetric key received.");
	
		
		String symKeyString = new String(decryptAsymmetric(privKey, encryptedSymKeyString));
		symmetricKey = stringToSecretKey(symKeyString);
		System.out.println(System.currentTimeMillis()+":  Decrypted symmetric key.");
		System.out.println();
		
		System.out.println(System.currentTimeMillis()+":  Masking in progress. ");
		System.out.println(System.currentTimeMillis()+":  Listening for user input..");
		MessageListener mytypeFaker = new MessageListener();
        mytypeFaker.start();
        
        System.out.println(System.currentTimeMillis()+":  Type a mesage to send ('q' to terminate sender and receiver).");
        message = "";
        System.out.print(System.currentTimeMillis()+":  ");
		while(!message.equals("q")) {
			message = "";
			Thread.sleep(5000);
			
			boolean faked = false;
			if(message.equals("")) {
				message = GenerateFakeMSG();
				System.out.print("Fake message generated.\n");
				faked = true;
			}
			
			System.out.println(System.currentTimeMillis()+":  Waiting for encrypted nonce...");
			int encrNonceLength = dataIn.readInt();
			byte[] encryptedNonce = new byte[encrNonceLength];
			System.out.println(System.currentTimeMillis()+":  Received nonce: decrypting nonce...");
			dataIn.readFully(encryptedNonce, 0, encrNonceLength);
			String nonce = new String(decryptSymmetric(encryptedNonce, symmetricKey));
			
			message = nonce + message;
			
			System.out.println(System.currentTimeMillis()+":  Generating message hash.");
			System.out.println(System.currentTimeMillis()+":  Encrypting message and hash.");
			byte[] encryptedMsg = encryptSymmetric(message.getBytes(), symmetricKey);
			byte[] encrHash = encryptSymmetric(generateHash(message), symmetricKey);
			dataOut.writeInt(encryptedMsg.length);
			dataOut.write(encryptedMsg);
			dataOut.writeInt(encrHash.length);
			dataOut.write(encrHash);
			if(!faked) {
				System.out.println(System.currentTimeMillis()+":  Message sent.");
			}
			
			message = message.substring(8);

			System.out.println("------------------------------------------------\n");
			System.out.print(System.currentTimeMillis()+":  ");
		}
		
		System.out.println("Quit request, terminating.");
	}
	
	//Main
	public static void main(String[] args) throws Exception{
		new Sender();
	}
	
	//Methods
    public static String GenerateFakeMSG() {
        double x = (Math.random() * 200) + 1;
        int string_length = (int) x;
        String ALPHA_NUMERIC_STRING = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
        StringBuilder builder = new StringBuilder();
        while (string_length-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
       // System.out.println("fake string: "  + builder.toString());
        return builder.toString();
      //return "dumMsg";
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
	
    public static byte[] decryptAsymmetric(/*byte[] privateKey,*/ PrivateKey key, byte[] inputData) throws Exception {
        //PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.PRIVATE_KEY, key);

        byte[] decryptedBytes = cipher.doFinal(inputData);

        return decryptedBytes;
    }
    
    public static SecretKey stringToSecretKey(String encodedKey) {
		byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
	
	public static String keyToString(PublicKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static byte[] generateHash(String mesage) throws Exception{
        MessageDigest md;
        md = MessageDigest.getInstance("MD5");
        byte[] thehashedMesage = md.digest(mesage.getBytes());
        return thehashedMesage;
    }
	
	class MessageListener extends Thread {

        public void run() {
            Scanner input = new Scanner(System.in);
            while (!message.equals("q")) {
                message = input.nextLine();
            }
            input.close();
            System.out.println(System.currentTimeMillis()+":  Message listener terminated.");
        }
    }
}


