import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//'terminal client'
public class Sender {
	private static Socket socket;
	private static DataInputStream dataIn;
	private static DataOutputStream dataOut;
	private static SecretKey symmetricKey;
	
	public static void main(String[] args) throws Exception{
		System.out.println("Sender has started.");
		System.out.println("Connecting to 0.0.0.0 port 1024");
		socket = new Socket("0.0.0.0", 1024);
		dataIn = new DataInputStream(socket.getInputStream());
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println("Connected to socket.");
		
		//Generating asymmetric keys
		System.out.println("Starting asymmetric encryption...");
		System.out.println("Generating public and private keys");
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
}
