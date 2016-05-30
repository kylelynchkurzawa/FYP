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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import fyp_common.XML_Device;
import fyp_common.XML_FileHandler;
import fyp_common.command_Object;

public class Admin_ListenForClients implements Runnable{
	
	private int timeout;
	private int port;
	private ServerSocket socketToClient;
	private XML_FileHandler xmlFH;
	private final String logFileChangeAlertSecurityCode = "fqipyrpquinfqbdkjvbqyre00pdlqslxsqlcwudmkhscmakbfqyi2r920fbdlct4e";
	private final String securitySendFileToAdminCode = "ad9qfldiquyduxcbqo8qidkqqou83r712ov1c179scwne118akqfnnkq7cq32za";
	private final String securityReplyToAdminCode = "fhwr8vbamzc0jqbapfhqrnkdalcpa9u9qgo1mpq98yd1vslvjfgdmfatfxiqliq";
	private Admin_GUI_Console adminGUI;
	private String downloadDirectory;
	
	public Admin_ListenForClients(int portNumber, int timeOutInSeconds, Admin_GUI_Console guiObj, String fileDownloadDirectory){
		if(portNumber <= 65535 && portNumber >=0){
			this.port = portNumber;
		} else{
			//default port number for listening for Log file changes
			this.port = 6235;
		}
		
		if(timeOutInSeconds > -1){
			this.timeout = timeOutInSeconds;			
		} else{
			this.timeout = 0;
		}
		try {
			this.socketToClient = new ServerSocket(this.port, this.timeout);
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		this.xmlFH = new XML_FileHandler();
		this.adminGUI = guiObj;
		if((new File(fileDownloadDirectory)).exists()){
			System.out.println("Directory Exists");
			this.downloadDirectory = fileDownloadDirectory;
		}
		else{
			System.out.println("Directory does not exist");
			this.downloadDirectory = "";
		}
		
	}
	
	public boolean loadXMLFile(String filepath){
		boolean b = false;
		
		if((new File(filepath).exists())){
			this.xmlFH.loadFile(filepath);
			b = true;
			System.out.println("Loaded XML file");
		}
		else{
			b = false;
		}
		return b;
	}

	private boolean checkIfDeviceIsMonitored(String ip){
		boolean b = false;
		
		try {
			List<XML_Device> monitoredDevices = this.xmlFH.getAllMonitoredDevices();
			for(int i=0; i<monitoredDevices.size(); i++){
				//if the ip matches return true
				if(monitoredDevices.get(i).getIp().equals(ip)){
					b = true;
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return b;
	}
	
	private void writeToUserGUI(String update){
		this.adminGUI.writeToUpdateBox(update);
	}
	
	private void wrtieTuUserGUI_LogUpdate(String update){
		this.adminGUI.writeToClientUpdateBox(update);
	}
	
	//TODO -- 'f' has linux file path and so you can't read it cause the path doesnt exist
	private boolean createFileLocally(File f){
		boolean b = false;
		
		System.out.println("Creating a file locally");
		String fileNameAndExtension = f.getName();
		System.out.println(this.downloadDirectory+"\\"+fileNameAndExtension);
		File brandNewFile = new File(this.downloadDirectory+"\\"+fileNameAndExtension);
		
		
		try {
			FileWriter fw = new FileWriter(brandNewFile);
			BufferedWriter bw = new BufferedWriter(fw);
			
			FileReader fr = new FileReader(f);
			BufferedReader br = new BufferedReader(fr);
			String line ="";
			
			while((line = br.readLine()) != null){
				bw.write(line);
				System.out.println("wrote a line in a file");
			}
			
			br.close();
			bw.close();
			fw.close();
			fr.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return b;
	}
	
	private void readAndExecuteCommandsFromClientToAdmin(command_Object commandObj, String remoteIP){
		
		if(!this.checkIfDeviceIsMonitored(remoteIP)){
			this.writeToUserGUI("Remote device not recognised. IP: "+remoteIP);
			return;
		}
		
		try{
			if(this.securitySendFileToAdminCode.equals(commandObj.getSecutiryString())){
				this.writeToUserGUI("Reply from client device: "+commandObj.getMessage());
				List<File> fileList = commandObj.getFileList();
				int filesCreated = 0;
				boolean b = false;
				for(File f : fileList){
					b = createFileLocally(f);
					if(b){
						filesCreated++;
					}
				}
				this.writeToUserGUI("Number of files created in the local Directory: "+filesCreated+"/"+fileList.size());
			}
			else if(this.logFileChangeAlertSecurityCode.equals(commandObj.getSecutiryString())){
				this.wrtieTuUserGUI_LogUpdate("Notice from "+remoteIP+": "+commandObj.getMessage());
			}
			else if(this.securityReplyToAdminCode.equals(commandObj.getSecutiryString())){
				this.writeToUserGUI("Notice from "+remoteIP+": "+commandObj.getMessage());
				return;
			}
			else{
				this.writeToUserGUI("Security code incorrect or not recognised, but is a monitored device.");
				return;
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
	}
	
	@Override
	public void run(){
		Socket sock = null;
		String remoteIP = null;
		System.out.println("Started Listener Thread");
		
		while(true){
			//always attempt to receive commands from the Clients
			try {
				//accept the socket and get the remote address
				System.out.println("In while loop");
				sock = this.socketToClient.accept();
				System.out.println("Accepted Socket");
				remoteIP = sock.getInetAddress().toString().replace("/", "");
				
				//check that device is monitored
				System.out.println("Remote Socket Address: "+sock.getRemoteSocketAddress());
				System.out.println("Local Socket Address: "+sock.getLocalSocketAddress());
				if(this.checkIfDeviceIsMonitored(remoteIP)){
					//pass the ip and inputs to the reader
					if(sock.isInputShutdown()){
						System.out.println("Socket input stream is closed");
					}
					System.out.println("Number of bytes available from input stream: "+sock.getInputStream().available());
					
						System.out.println("Attempting to get object input stream");
						//get the input stream and read the inputs
						
						ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
						System.out.println("Got object input stream from socket");
						Object obj = ois.readObject();
						//close the stream
						ois.close();
						System.out.println("Read object from object input stream");
						try{
							if(obj instanceof command_Object){
								this.readAndExecuteCommandsFromClientToAdmin((command_Object)obj, remoteIP);
							}
							else{
								System.out.println("Received an object that wasn't a command Object");
							}
						}
						catch(Exception e){
							//possible null pointer exceptions so just catch them for the moment
							e.printStackTrace();
						}
					
				}
				else{
					System.out.println("Device is not monitored, closing socket.");
				}
				//close the socket
				sock.close();
				
			}//end try 
			catch (IOException | ClassNotFoundException e) {
				System.out.println("Caught an exception");
				e.printStackTrace();
			}//end catch
			finally{
				System.out.println("Inside Finally");
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
	
}
