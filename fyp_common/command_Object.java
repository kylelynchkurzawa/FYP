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

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class command_Object implements Serializable{
	
	private static final long serialVersionUID = 1L;
	
	private List<File> fileList;
	private String command;
	private String security_string;
	private String message;
	
	private String actionOrder;
	private String fileName;
	private String fileText;
	
	private String newIP;
	private int newPort;
		
	public command_Object(){
		this.fileList = new ArrayList<File>();
		this.command = "";
		this.security_string= "";
		this.message = "";
	}
	
	public command_Object(List<File> listOfFiles, String object_Command, String security, String message){
		checkAndInitializeFileList(listOfFiles);
		this.command = object_Command;
		this.security_string = security;
		this.message = message;
	}
	
	public List<File> getFileList(){
		return this.fileList;
	}
	public String getCommand(){
		return this.command;
	}
	public String getSecutiryString(){
		return this.security_string;
	}
	public String getMessage(){
		return this.message;
	}
	
	//specifically getters and setters for going TO the client device
	public String getActionOrder(){
		return this.actionOrder;
	}
	public String getFileName(){
		return this.fileName;
	}
	public String getFileText(){
		return this.fileText;
	}
	public String getNewIP(){
		return this.newIP;
	}
	public int getNewPort(){
		return this.newPort;
	}
	
	public void setActionOrder(String actionOrder){
		this.actionOrder = actionOrder;
	}
	public void setFileName(String fileName){
		this.fileName = fileName;
	}
	public void setFileText(String fileText){
		this.fileText = fileText;
	}
	public void setNewIP(String ipAddress){
		this.newIP = ipAddress;
	}
	public void setNewPort(int port){
		this.newPort = port;
	}
	
	private void checkAndInitializeFileList(List<File> listOfFiles){
		this.fileList = new ArrayList<File>();
		
		//check if the list is empty or null
		if(listOfFiles==null){
			return;
		}
		else if(listOfFiles.isEmpty()){
			return;
		}
		else{
			for(int i=0; i<listOfFiles.size(); i++){
				if(listOfFiles.get(i).exists()){
					this.fileList.add(listOfFiles.get(i));
				}
			}
		}
	}
}
