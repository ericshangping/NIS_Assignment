import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
		System.out.println("Sender has started.");
		System.out.println("Connecting to 0.0.0.0 port 1024");
		socket = new Socket("0.0.0.0", 1024);
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println("Connected to socket.");
		
		//Generating asymmetric keys
		System.out.println("Starting asymmetric encryption...");
		System.out.println("Generating public and private keys.");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(512); //Number of bits in both keys
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();    //This is the public key
		PrivateKey privKey = keyPair.getPrivate(); //This is the private key
		
		System.out.println("Sending public key...");
		String publicKeyString = keyToString(pubKey);
		dataOut.writeUTF(publicKeyString);
		
		System.out.println("Waiting to receive encrypted symmetric key...");
		int encrSymKeyLength = dataIn.readInt();
		byte[] encryptedSymKeyString = new byte[encrSymKeyLength];
		dataIn.readFully(encryptedSymKeyString, 0, encrSymKeyLength);
		System.out.println("Encrypted symmetric key received.");
		//System.out.println("TEST: encrypted symmetric key: "+new String(encryptedSymKeyString)); //testprint
		
		String symKeyString = new String(decryptAsymmetric(privKey, encryptedSymKeyString));
		symmetricKey = stringToSecretKey(symKeyString);
		System.out.println("Decrypted symmetric key.");
		System.out.println();
		
		System.out.println("Masking in progress. ");
		System.out.println("Listening for user input..");
		MessageListener mytypeFaker = new MessageListener();
        mytypeFaker.start();
        
        message = "";
		while(!message.equals("q")) {
			boolean faked = false;
			if(message.equals("")) {
				message = GenerateFakeMSG();
				faked = true;
			}
			
			byte[] encryptedMsg = encryptSymmetric(message.getBytes(), symmetricKey);
			dataOut.writeInt(encryptedMsg.length);
			dataOut.write(encryptedMsg);
			if(!faked) {
				System.out.println("Message sent.");
			}
			
			message = "";
			Thread.sleep(5000);
		}
	
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
	
	class MessageListener extends Thread {

        public void run() {
            Scanner input = new Scanner(System.in);
            while (message != "q") {
                System.out.println("Please type mesage to send. (type q to close)");
                message = input.nextLine();

            }
            input.close();
        }

    }
}


