import java.net.Socket;
import java.util.Scanner;

//'terminal client'
public class Sender {
	private static Socket socket;
	
	public static void main(String[] args) throws Exception{
		System.out.println("Sender has started.");
		System.out.println("Connecting to 0.0.0.0 port 1024");
		socket = new Socket("0.0.0.0", 1024);
	}
	
	class MessageListener extends Thread{
		Socket socket;
		Scanner scInputStream;
		
		public MessageListener(Socket socket) {
			this.socket = socket;
		}
		
		public void run() {
			try {
				scInputStream = new Scanner(socket.getInputStream());
				while(true) {
					String message = 
				}
			}catch(Exception e) {
				System.out.println("Error has occurred when listening for messages.");
				e.printStackTrace();
			}
		}
	}
}
