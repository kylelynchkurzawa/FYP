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

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import fyp_common.command_Object;

public class Client_ListenForAdminCommands implements Runnable{
	private int port;
	private int timeout;
	private String securityCheck;
	private Client_Device client;
	private Client_SuricataHandler suricataHandler;
	
	private final String securitySendFileToAdminCode = "ad9qfldiquyduxcbqo8qidkqqou83r712ov1c179scwne118akqfnnkq7cq32za";
	private final String securityReplyToAdminCode = "fhwr8vbamzc0jqbapfhqrnkdalcpa9u9qgo1mpq98yd1vslvjfgdmfatfxiqliq";
	
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
	
	public Client_ListenForAdminCommands(int portNumber, int timeOutInSeconds, Client_Device client) throws IOException{
		
		if(portNumber <= 65535 && portNumber >=0){
			this.port = portNumber;
		} else{
			//default port number for listening for commands
			this.port = 6236;
		}
		
		if(timeOutInSeconds > -1){
			this.timeout = timeOutInSeconds;			
		} else{
			this.timeout = 0;
		}
		this.suricataHandler = new Client_SuricataHandler();
		//64 random characters by mashing my keyboard like a mad man
		this.securityCheck = "advaskjdn379e298rwygfdwkndq836782hkqwndoqwduq837y3ejpi92uyibqkn";
	}
	
	//set the main class
	public void setClient_Device(Client_Device Client){
		if(Client != null){
			this.client = Client;			
		}
	}
	
	//-- commands from Admin --//
	
	//change who the watchers send notifications to
	private boolean command_setAllWatcherSockets(String ipAddress, int port){
		if(this.client == null){
			return false;
		}
		System.out.println("Seting socket to ip: "+ipAddress+" on port:"+port);
		if(ipAddress.isEmpty() || ipAddress == null){
			return false;
		}
		else if(port < 0 || port > 65535){
			return false;
		}
		else{
			this.client.setAllWatcherSockets(ipAddress, port);
			return true;
		}		
	}
	
	//stop the log watchers
 	private void command_stopAllWatchers(){
		if(this.client != null){
			this.client.stopAllWatchers();
		}
	}
	
	//start the log watchers
	private void command_startAllWatchers(){
		if(this.client != null){
			this.client.startAllWatchers();
		}
	}
	
	//restart the log watchers
	private void command_restartAllWatchers(){
		if(this.client != null){
			command_stopAllWatchers();
			
			//wait a little bit for each thread to naturally stop
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			
			command_startAllWatchers();
		}
	}

	//get log file for admin
	private File command_getLogFile(String logFileName){
		
		File f = this.client.getLogFile(logFileName);
		return f;
	}
	
	//restart Suricata
	private void command_restartSuricata(){
		this.suricataHandler.restartSuricataEngine();
	}
	
	//start Suricata
	private void command_startSuricata(){
		this.suricataHandler.startSuricataEngine();
	}
	
	//stop Suricata
	private void command_stopSuricata(){
		this.suricataHandler.stopSuricataEngine();
	}
	
	//check if a rule is being used
	private boolean command_isRuleBeingUsed(String filename){
		return this.suricataHandler.isRuleFileUsed(filename);
	}
	
	//remove a rule file from the system
	private boolean command_removeRuleFile(String filename){
		return this.suricataHandler.removeRuleFile(filename);
	}
	
	//create a new rule file for the system
	private boolean command_createNewRuleFile(String ruleFileName, String ruleText){
		return this.suricataHandler.createNewRuleFile(ruleFileName, ruleText);
	}
	
	//change the rule action order for suricata
	private boolean command_changeActionOrder(String order){
		List<Integer> actionOrder = new ArrayList<Integer>();
		String[] numbers = order.split("\\B");
		for(int i=0; i<numbers.length; i++){
			actionOrder.add(Integer.parseInt(numbers[i]));
		}
		return this.suricataHandler.changeActionOrder(actionOrder);
	}
	
	//change the contents of a rule file
	private boolean command_editRuleFile(String ruleFileName, String ruleFileText){
		return this.suricataHandler.editRuleFile(ruleFileName, ruleFileText);
	}
	
	//get a rule file for the admin
	private File command_getRuleFile(String ruleFileName){
		return this.suricataHandler.getRuleFile(ruleFileName);
	}
	
	//get all the rule files for the admin
	private List<File> command_getAllRuleFiles(){
		return this.suricataHandler.getAllRuleFiles();
	}
	
	//-- Method to read and run Admin's commands --//
	
	//read commands will hopefully follow this format
	// 'securityString'*'command'*'parameters'
	private void readAndExecuteCommands(command_Object commandObj, String remoteIP, int port){
		
		//prevent empty command from entering the app
		if(commandObj.getCommand().isEmpty() || commandObj.getCommand()==null){
			System.out.println("Refused commands from remote device because commands were empty.");
			return;
		}
		//check if the first parameter doesn't match the security string
		if(!commandObj.getSecutiryString().equals(this.securityCheck)){
			System.out.println("Refused commands from remote device because of incorrect clearence.");
			return;
		}
		else{
			System.out.println("Security cleared.");
			boolean b = false;
			String filename = "";
			String ruletext = "";
			String order = "";
			String command = commandObj.getCommand();
			switch(command){
			case(c_setAllWatcherSockets):
				System.out.println("Calling method to change Log Update socket");
				this.port = port;
				b = this.command_setAllWatcherSockets(commandObj.getNewIP(), commandObj.getNewPort());
				//send confirmation to admin
				this.sendMessageToAdmin("Log Update socket And Response Port changed: "+b, remoteIP, this.port);
				break;
			case(c_stopAllWatchers):
				System.out.println("Calling methoid to stop all watchers");
				this.command_stopAllWatchers();
				//send confirmation to admin
				this.sendMessageToAdmin("Watcher threads stopped.", remoteIP, this.port);
				break;
			case(c_startAllWatchers):
				System.out.println("Calling method to start all watchers");
				this.command_startAllWatchers();
				//send confirmation to admin
				this.sendMessageToAdmin("Watcher treads started.", remoteIP, this.port);	
				break;
			case(c_restartAllWatchers):
				System.out.println("Calling method to restart all watchers");
				this.command_restartAllWatchers();
				//send confirmation to admin
				this.sendMessageToAdmin("Watcher threads restarted.", remoteIP, this.port);
				break;
			case(c_getLogFile):
				String logFileName = commandObj.getFileName();
				System.out.println("Calling method to get a log file");
				File logFile = this.command_getLogFile(logFileName);
				//send log file back to admin
				this.sendFileToAdmin(logFile, ("Log file sent to admin. File was: "+logFile.getName()), remoteIP, this.port);
				break;
			case(c_restartSuricata):
				System.out.println("Callingmethod to restart Suricata");
				this.command_restartSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("Restarted Suricata.", remoteIP, this.port);
				break;
			case(c_startSuricata):
				System.out.println("Starting Suricata");
				this.command_startSuricata();
				//send confirmation to admin
				System.out.println("Sendng confirmation message");
				this.sendMessageToAdmin("Suricata Engine started.", remoteIP, this.port);
				break;
			case(c_stopSuricata):
				this.command_stopSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("Suricata Engine stopped.", remoteIP, this.port);
				break;
			case(c_isRuleBeingUsed):
				System.out.println("Calling method to check if a rule file is being used");
				filename = commandObj.getFileName();
				b = this.command_isRuleBeingUsed(filename);
				//send confirmation to admin
				this.sendMessageToAdmin("Rule file being used: "+b, remoteIP, this.port);
				break;
			case(c_removeRuleFile):
				this.command_stopSuricata();
				filename = commandObj.getFileName();
				System.out.println("Calling method to remove a rule file");
				b = this.command_removeRuleFile(filename);			
				this.command_startSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("Rule file removed: "+b, remoteIP, this.port);
				break;
			case(c_createNewRuleFile):
				this.command_stopSuricata();
				filename = commandObj.getFileName();
				ruletext = commandObj.getFileText();
				System.out.println("Calling method to create a new rule file");
				b = this.command_createNewRuleFile(filename, ruletext);
				this.command_startSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("New rule file created: "+b, remoteIP, this.port);
				break;
			case(c_changeActionOrder):
				this.command_stopSuricata();
				order = commandObj.getActionOrder();
				System.out.println("Calling method to change action order");
				b = this.command_changeActionOrder(order);
				this.command_startSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("Action order changed: "+b, remoteIP, this.port);
				break;
			case(c_editRuleFile):
				this.command_stopSuricata();
				filename = commandObj.getFileName();
				ruletext = commandObj.getFileText();
				System.out.println("Calling method to edit a rule file");
				b = this.command_editRuleFile(filename, ruletext);
				this.command_startSuricata();
				//send confirmation to admin
				this.sendMessageToAdmin("Rule file edited: "+b, remoteIP, this.port);
				break;
			case(c_getRuleFile):
				filename = commandObj.getFileName();
				System.out.println("Calling method to get a rule file");
				File f = this.command_getRuleFile(filename);
				this.sendFileToAdmin(f, ("Rule file returned: "+f.getName()), remoteIP, this.port);
				break;
			case(c_getAllRuleFiles):
				System.out.println("Calling method to get all rule files");
				List<File> fileList = this.command_getAllRuleFiles();
				this.sendMultipleFilesToAdmin(fileList, "All rule files listed in Suricata.yaml", remoteIP, this.port);
				break;
			default:
				System.out.println("Unknown Command: "+command);
				System.out.println("Nothing executed.");
				break;
			
			}
		}
	}
	
	//--- Methods to reply to the Admin ---//
	
	//send a message to the admin
	private void sendMessageToAdmin(String message, String adminIP, int adminPort){
		ObjectOutputStream oos = null;
		Socket s = null;
		try {
			System.out.println("Sending message to address: "+adminIP+" on port: "+adminPort);
			s = new Socket(adminIP, adminPort);
			if(s.isConnected()){
				System.out.println("Socket connected to admin");
			}
			
			oos = new ObjectOutputStream(s.getOutputStream());
			System.out.println("Got object output stream");
			command_Object co = new command_Object( null, "no command", this.securityReplyToAdminCode, message);
			
			System.out.println(co.getMessage());			
			
			oos.writeObject(co);
			System.out.println("Wrote object to output stream");
			oos.flush();
			//oos.flush();
			System.out.println("Flushed once");
			oos.close();
			s.close();
			System.out.println("Message sent to Admin");
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally{
			if(s.isClosed()){
				if(!s.isOutputShutdown()){
					try {
						oos.flush();
						oos.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				try {
					s.close();
				} catch (IOException e) {
					e.printStackTrace();
				}				
			}
		}
	}
	
	//send a single file to the admin
	private void sendFileToAdmin(File fileToSend, String message, String adminIP, int adminPort){
		Socket s = null;
		ObjectOutputStream outStream = null;
		try {
			//get sockets and streams needed to convert file into a byte array
			System.out.println("Sending message to address: "+adminIP+" on port: "+adminPort);
			s = new Socket(adminIP, adminPort);
			outStream = new ObjectOutputStream(s.getOutputStream());
			outStream.flush();
			
			List<File> fileList = new ArrayList<File>();
			fileList.add(fileToSend);
			
			command_Object co = new command_Object(fileList, "no command", this.securitySendFileToAdminCode, message);
			
			outStream.writeObject(co);
			outStream.flush();
			outStream.flush();
			outStream.close();	
			s.close();
			System.out.println("A single file sent to Admin");
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally{
			if(s.isClosed()){
				if(!s.isOutputShutdown()){
					try {
						outStream.flush();
						outStream.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				try {
					s.close();
				} catch (IOException e) {
					e.printStackTrace();
				}				
			}
		}
	}
	
	//send multiple files to the admin at once
	private void sendMultipleFilesToAdmin(List<File> files, String message, String adminIP, int adminPort){
		Socket s = null;
		ObjectOutputStream outStream = null;
		try {
			//get sockets and streams needed to convert file into a byte array
			System.out.println("Sending message to address: "+adminIP+" on port: "+adminPort);
			s = new Socket(adminIP, adminPort);
			
			outStream = new ObjectOutputStream(s.getOutputStream());
			outStream.flush();
			command_Object co = new command_Object(files, "no command", this.securitySendFileToAdminCode, message);
			
			outStream.writeObject(co);
			outStream.flush();
			outStream.flush();
			outStream.close();
			s.close();
			
			System.out.println("Sent multiple files to Admin");
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally{
			if(s.isClosed()){
				if(!s.isOutputShutdown()){
					try {
						outStream.flush();
						outStream.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				try {
					s.close();
				} catch (IOException e) {
					e.printStackTrace();
				}				
			}
		}
	}
	
	@Override
	public void run(){
		ServerSocket sSock = null;
		Socket sock = null;
		String remoteIP = null;
		int port = -1;
		System.out.println("Inside run method of Listener");
		while(true){
			//always attempt to receive commands from the Admin
			try {
				Thread.sleep(125);
				
				System.out.println("Inside Listener while loop");
				//accept the socket and get the remote address
				sSock = new ServerSocket(this.port, this.timeout);
				sock = sSock.accept();
				remoteIP = sock.getInetAddress().toString().replace("/", "");
				port = sock.getLocalPort();
				System.out.println("Admin Listener: Accepted socket");
				//get the input stream and read the inputs
				ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
				Object objectFromStream = ois.readObject();
				System.out.println("Object Read from object output Stream");
				//close the socket and streams
				ois.close();
				sock.close();
				sSock.close();
				System.out.println("Closed socket and stream.");
				
				System.out.println("Checking object from stream...");
				//pass the ip and inputs to the reader
				try{
					if(objectFromStream instanceof command_Object){
						System.out.println("Command object received");
						readAndExecuteCommands((command_Object)objectFromStream, remoteIP, port);
					}
					else{
						System.out.println("Unknown object received, ignoring it...");
					}
				}
				catch(Exception e){
					//possible null pointer exceptions so just catch them for the moment
					e.printStackTrace();
				}
			}//end try 
			catch (IOException | ClassNotFoundException | InterruptedException e) {
				e.printStackTrace();
			}//end catch
			finally{
				if(!sock.isClosed()){
					try {
						sock.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}//end finally
		}//end while
	}//end run	
}//end class
