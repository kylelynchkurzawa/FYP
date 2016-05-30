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
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

import org.apache.commons.io.input.ReversedLinesFileReader;
import fyp_common.command_Object;

public class Client_WatchForRuleTriggers implements Runnable{
	
	private LinkedBlockingQueue<command_Object> queue;
	private boolean run;
	private File monitoredFile;
	private long timeLastModified;
	private final String logFileUpdateSecurityString= "fqipyrpquinfqbdkjvbqyre00pdlqslxsqlcwudmkhscmakbfqyi2r920fbdlct4e";
	
	public Client_WatchForRuleTriggers(String path, LinkedBlockingQueue<command_Object> blockingQueue) throws Exception{
		
		if((path == null) || (!(new File(path).exists())) ){
			throw new Exception("Illegal Filepath");
		}
		
		this.run = false;
		this.queue = blockingQueue;
		this.monitoredFile = new File(path);
		this.timeLastModified = this.monitoredFile.lastModified();
	}
	
	public void setToRun(boolean isToRun){
		this.run = isToRun;
	}

	@Override
	public void run() {
		System.out.println("Watcher running");
		List<String> content = new ArrayList<String>();
		while(this.run){
			
			try {
				Thread.sleep(250);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			
			//if it hasn't been modified, than no need to do anything
			if(this.timeLastModified != this.monitoredFile.lastModified()){
				
				//System.out.println("Rule Triggered!");
				
				//get the content from the new entry in the log file				
				try {
					content = getLatestContent();
				} catch (FileNotFoundException e) {
					e.printStackTrace();
				}
				
				//alert the admin by sending them the message generated
				System.out.println(this.monitoredFile.getName()+" was edited.");
				
				//send alert with content
				sendRuleTriggerToAdmin(content);
				
				//after sending the alert save the new time modified
				this.timeLastModified = this.monitoredFile.lastModified();
				//clear the content from the last modification
				content.clear();
			}
		}
		System.out.println("Watcher stopped");
	}
	
	public File getLogFile(){
		if(this.monitoredFile != null){
			return this.monitoredFile;
		}
		else{
			return null;
		}
	}
	
	public String getLogFileName(){
		return this.monitoredFile.getName();
	}
	
	private void sendRuleTriggerToAdmin(List<String> content){
		
		try {
			String message = this.monitoredFile.getPath();
			//add all the alerts to the print stream
			for(int i=0; i<content.size(); i++){
				message = message.concat(" "+content.get(i));
			}
			
			command_Object co = new command_Object(null, "", this.logFileUpdateSecurityString, message);
			queue.put(co);
			
			
			System.out.println("Update of log file queued for sending to admin from file: "+this.getLogFileName());
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private List<String> getLatestContent() throws FileNotFoundException{
		String content = null;
		int linecount = 1;
		List<String> latest_entries = new ArrayList<String>();
		//assuming Suricata does not enter \n chars on purpose and that
		//the new entries are always on one single line
				
		try{
			@SuppressWarnings("resource")
			ReversedLinesFileReader rlfr = new ReversedLinesFileReader(this.monitoredFile);
			for(int i=0; i<linecount; i++){
				content = rlfr.readLine();
				latest_entries.add(content);
			}
		}
		catch(Exception e){
			System.out.println(e);
		}
		
		return latest_entries;
	}
}
