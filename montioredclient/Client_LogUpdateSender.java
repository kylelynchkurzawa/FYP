/*
Student: Kyle Lynch-Kurzawa
Student ID: 12399541
Supervisor: Michael Schukat
Project Code: MS2
University: National University of Ireland Galway
Code: CT413
Course: Computer Science and Information Technology - 4BCT
Project: Network Intrusion Detection
*/

package montioredclient;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.concurrent.LinkedBlockingQueue;

import fyp_common.command_Object;

public class Client_LogUpdateSender implements Runnable {

	private LinkedBlockingQueue<command_Object> queue;
	private String ipAddress;
	private int port;
	private boolean runFlag;
	private Socket socketToAdmin;
	private ObjectOutputStream oos;
	
	public Client_LogUpdateSender(LinkedBlockingQueue<command_Object> blockingQueue, int portNumber, String AdminIPAddress) {

		queue = blockingQueue;
		this.runFlag = false;
		if (portNumber <= 65535 && portNumber >= 0) {
			this.port = portNumber;
		} else {
			// default port number for sending commands
			this.port = 6236;
		}

		if (!AdminIPAddress.isEmpty() && AdminIPAddress != null) {
			this.ipAddress = AdminIPAddress;
		} else {
			this.ipAddress = "";
		}
	}
	
	public boolean setSocketAddressAndPort(String ipAddressToAdmin, int portToAdmin){
		boolean b =false;
		
		if(portToAdmin <= 65535 && portToAdmin >= 0) {
			this.port = portToAdmin;
		} else {
			// default port number for sending commands
			this.port = 6236;
		}

		if (!ipAddressToAdmin.isEmpty() && ipAddressToAdmin != null) {
			this.ipAddress = ipAddressToAdmin;
		} else {
			this.ipAddress = "";
		}
		b=true;
		
		return b;
	}

	public void setRunFlag(boolean run){
		this.runFlag = run;
	}
	
	@Override
	public void run() {
		command_Object commandObj = null;
		while(runFlag) {
			
			try {
				Thread.sleep(500);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			
			if(this.ipAddress.isEmpty()){
				System.out.println("IpAddress is empty");
			}
			if(this.socketToAdmin == null){
				System.out.println("Socket is empty");
			}
					
			try {				
				commandObj = queue.take();
				System.out.println("Got object from Queue to send to admin");
				this.socketToAdmin = new Socket(this.ipAddress, this.port);
				
				//create a print stream
				this.oos = new ObjectOutputStream(socketToAdmin.getOutputStream());
				//wait until there's an object in the queue and then send it
				
				//tell the print stream to send it's stuff off
				this.oos.writeObject(commandObj);
				this.oos.flush();
				this.oos.close();
				System.out.println("Message sent to ip: "+ this.socketToAdmin.getRemoteSocketAddress());
			} 
			catch (Exception e) {
				e.printStackTrace();
			}
			finally{
				if(!this.socketToAdmin.isClosed()){
					try {
						this.socketToAdmin.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}//end finally
		}//end while loop
	}//end run method
}