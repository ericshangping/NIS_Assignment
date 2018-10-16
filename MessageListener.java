import java.io.DataInputStream;
import java.net.Socket;

public class MessageListener extends Thread{
	private Socket socket;
	private DataInputStream dataIn;
	
	public MessageListener(Socket socket) {
		this.socket = socket;
	}
	
	public void run() {
		System.out.println("Listener started.");
		try {
			dataIn = new DataInputStream(socket.getInputStream());
			while(true) {
				//String message = 
			}
		}catch(Exception e) {
			System.out.println("Error has occurred when listening for messages.");
			e.printStackTrace();
		}
	}
}
