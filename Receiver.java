import java.net.*;

//'server'
public class Receiver {
	private static ServerSocket serverSocket;
	
	public static void main(String[] args) throws Exception{
		System.out.println("Server has started");
		
		serverSocket = new ServerSocket(1024);
		
		while(true) {
			Socket socket = null;
			socket = serverSocket.accept();
		}
	}
}


