import java.io.*;
import java.net.Socket;

//'terminal client'
public class Sender {
	private static Socket socket;
	private static DataOutputStream dataOut;
	
	public static void main(String[] args) throws Exception{
		System.out.println("Sender has started.");
		System.out.println("Connecting to 0.0.0.0 port 1024");
		socket = new Socket("0.0.0.0", 1024);
		dataOut = new DataOutputStream(socket.getOutputStream());
		System.out.println("Connected to socket.");
		
		MessageListener listener = new MessageListener(socket);
		listener.start();
		
		
	}
	
}
