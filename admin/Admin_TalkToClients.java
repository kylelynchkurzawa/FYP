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

package admin;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import fyp_common.command_Object;

public class Admin_TalkToClients {
	
	private String ClientIPAddress;
	private int port;
	
	private Socket socketToClient;
	private ObjectOutputStream oos;
	private String TalkToClientSecurityCheck;
		
	private final String c_setAllWatcherSockets = "c_SetAllWatcherSockets";
	private final String c_stopAllWatchers = "c_stopAllWatchers";
	private final String c_startAllWatchers = "c_startAllWatchers";
	private final String c_restartAllWatchers = "c_restartAllWatchers";
	private final String c_getLogFile = "c_getLogFile";
	private final String c_restartSuricata= "c_restartSuricata";
	private final String c_startSuricata = "c_startSuricata";
	private final String c_stopSuricata = "c_stopSuricata";
	private final String c_isRuleBeingUsed = "c_isRuleBeingUsed";
	private final String c_removeRuleFile = "c_removeRuleFile";
	private final String c_createNewRuleFile = "c_createNewRuleFile";
	private final String c_changeActionOrder = "c_changeActionOrder";
	private final String c_editRuleFile = "c_editRuleFile";
	private final String c_getRuleFile = "c_getRuleFile";
	private final String c_getAllRuleFiles = "c_getAllRuleFiles";
	
	public Admin_TalkToClients(int portNumber, String ClientIPAddress) throws IOException{
		if(portNumber <= 65535 && portNumber >=0){
			this.port = portNumber;
		} else{
			//default port number for sending commands
			this.port = 6236;
		}
		
		if(!ClientIPAddress.isEmpty() && ClientIPAddress != null){
			this.ClientIPAddress = ClientIPAddress;			
		} else{
			this.ClientIPAddress = "";
		}
		this.TalkToClientSecurityCheck = "advaskjdn379e298rwygfdwkndq836782hkqwndoqwduq837y3ejpi92uyibqkn";		
		this.socketToClient = new Socket(this.ClientIPAddress, this.port);
	}
	
	private void reinitialiseSocket(){
		try {
			this.socketToClient = new Socket(this.ClientIPAddress, this.port);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e){
			e.printStackTrace();
		}
	}
	
	//change what device your speaking to
	public boolean setIPAddressAndPort(String ipAddress, int portNumber){
		boolean b = false;
		
		if(portNumber <= 65535 && portNumber >=0){
			this.port = portNumber;
			b = true;
		} else{
			//default port number for sending commands
			this.port = 6236;
		}
		
		if(!ipAddress.isEmpty() && ipAddress != null){
			this.ClientIPAddress = ipAddress;
			b = true;
		} else{
			this.ClientIPAddress = "";
		}
		
		reinitialiseSocket();
		
		return b;
	}
	
	//return if the command to set the watchers was sent
	public boolean client_setAllWatcherSockets(String ipAddress, int port){
		command_Object co = new command_Object(null, this.c_setAllWatcherSockets, this.TalkToClientSecurityCheck, null);
		co.setNewIP(ipAddress);
		co.setNewPort(port);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to stop the watchers was sent
	public boolean client_stopAllWatchers(){
		command_Object co = new command_Object(null, this.c_stopAllWatchers, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to start the watchers was sent
	public boolean client_startAllWatchers(){
		command_Object co = new command_Object(null, this.c_startAllWatchers, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to restart the watchers was sent
	public boolean client_restartAllWatchers(){
		command_Object co = new command_Object(null, this.c_restartAllWatchers, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to get a log file was sent
	public boolean client_getLogFile(String fileName){
		command_Object co = new command_Object(null, this.c_getLogFile, this.TalkToClientSecurityCheck, null);
		co.setFileName(fileName);
		return this.sendMessageToClient(co);
	}

	//return if the command to restart suircata was sent
	public boolean client_restartSuricata(){
		command_Object co = new command_Object(null, this.c_restartSuricata, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to start suricata was sent
	public boolean client_startSuricata(){
		
		command_Object co = new command_Object(null, this.c_startSuricata, this.TalkToClientSecurityCheck, null);
		System.out.println("Sending message to client");
		return this.sendMessageToClient(co);
	}
	
	//return if the command to stop suricata was sent
	public boolean client_stopSuricata(){
		command_Object co = new command_Object(null, this.c_stopSuricata, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	//return if the command to check if a rule file is being used was sent
	public boolean client_isRuleBeingUsed(String ruleFileName){
		command_Object co = new command_Object(null, this.c_isRuleBeingUsed, this.TalkToClientSecurityCheck, null);
		co.setFileName(ruleFileName);
		return this.sendMessageToClient(co);
	}
	
	//return if the command to remove a rule file was sent
	public boolean client_removeRuleFile(String ruleFileNameToRemove){
		command_Object co = new command_Object(null, this.c_removeRuleFile, this.TalkToClientSecurityCheck, null);
		co.setFileName(ruleFileNameToRemove);
		return this.sendMessageToClient(co);
	}
	
	//return if the command to create a new rule file was sent
	public boolean client_createNewRuleFile(String ruleFileName, String ruleFileText){
		command_Object co = new command_Object(null, this.c_createNewRuleFile, this.TalkToClientSecurityCheck, null);
		co.setFileName(ruleFileName);
		co.setFileText(ruleFileText);
		return this.sendMessageToClient(co);
	}
	
	//return if the command to change the rule action order was sent
	public boolean client_changeActionOrder(String actionOrderNumberString){
		command_Object co = new command_Object(null, this.c_changeActionOrder, this.TalkToClientSecurityCheck, null);
		co.setActionOrder(actionOrderNumberString);
		return this.sendMessageToClient(co);
	}
	
	//return if the command to edit a rule file was sent
	public boolean client_editRuleFile(String ruleFileName, String ruleFileText){
		command_Object co = new command_Object(null, this.c_editRuleFile, this.TalkToClientSecurityCheck, null);
		co.setFileName(ruleFileName);
		co.setFileText(ruleFileText);		
		return this.sendMessageToClient(co);		
	}
	
	//return if the command to get a rule file was sent
	public boolean client_getRuleFile(String ruleFileName){
		command_Object co = new command_Object(null, this.c_getRuleFile, this.TalkToClientSecurityCheck, null);
		co.setFileName(ruleFileName);
		
		return this.sendMessageToClient(co);	
	}
	
	//return if the command to get all rule files was sent
	public boolean client_getAllRuleFiles(){
		command_Object co = new command_Object(null, this.c_getAllRuleFiles, this.TalkToClientSecurityCheck, null);
		
		return this.sendMessageToClient(co);
	}
	
	private boolean sendMessageToClient(command_Object commandObj){
		boolean b = false;
		
		if(this.ClientIPAddress.isEmpty()){
			System.out.println("IpAddress is empty");
			return false;
		}
		if(this.socketToClient == null){
			return false;
		}
				
		try {
			//create a print stream
			this.oos = new ObjectOutputStream(socketToClient.getOutputStream());
			
			//tell the print stream to send it's stuff off
			this.oos.writeObject(commandObj);
			this.oos.flush();
			this.oos.close();
			System.out.println("Message sent to ip: "+ this.socketToClient.getRemoteSocketAddress());
			b = true;
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
		finally{
			try {
				if(!this.socketToClient.isOutputShutdown()){
					this.oos.flush();
					this.oos.close();
				}				
			} catch (IOException e) {
				e.printStackTrace();
			}
			if(!this.socketToClient.isClosed()){
				try {
					this.socketToClient.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
		return b;		
	}
}
