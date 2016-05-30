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

package fyp_common;

public class XML_Device {
	
	private boolean admin;
	private String ip;
	private String hostname;
	private int port;
	private String user;
	private String password;
	
	public XML_Device(){
		this.admin = false;
		this.ip = null;
		this.hostname = null;
		this.port = -1;
		this.user = null;
		this.password = null;
	}
	
	public XML_Device(boolean isAdmin, String ipAddress, 
					  String host, int portNumber, 
					  String username, String userPassword){
		
		this.admin = isAdmin;
		this.ip = ipAddress;
		this.hostname = host;
		this.port = portNumber;
		this.user = username;
		this.password = userPassword;
	}

	public boolean isAdmin(){
		return this.admin;
	}
	public String getIp(){
		return this.ip;
	}
	public String getHostname(){
		return this.hostname;
	}
	public int getPortNumber(){
		return this.port;
	}
	public String getUsername(){
		return this.user;
	}
	public String getPassword(){
		return this.password;
	}
	
	@Override
	public String toString(){
		return (this.getIp()+"\n"+
				this.getHostname()+"\n"+
				this.getPortNumber()+"\n"+
				this.getUsername()+"\n"+
				this.getPassword()+"\n\n");
	}

}
