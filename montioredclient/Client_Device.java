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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

import fyp_common.command_Object;

public class Client_Device {
		
	private Client_ListenForAdminCommands listener1;
	private Client_LogUpdateSender logSender;
	private LinkedBlockingQueue<command_Object> queue;
	private List<Client_WatchForRuleTriggers> watcherList;
	private List<Thread> watcherThreads;
	
	private Thread listenerThread;	
	private Thread logSenderThread;
	
	public Client_Device(List<String> logFilePaths, int port, int timeout) throws Exception{
		
		queue = new LinkedBlockingQueue<command_Object>();
		this.logSender = new Client_LogUpdateSender(queue, timeout, "");
		this.logSender.setRunFlag(true);
		this.watcherList = new ArrayList<Client_WatchForRuleTriggers>();
		this.watcherThreads = new ArrayList<Thread>();
		Client_WatchForRuleTriggers tempWatcher = null;
		Thread tempThread = null;
		
		//create a watcher for all log files
		for(int i=0; i<logFilePaths.size(); i++){
			tempWatcher = new Client_WatchForRuleTriggers(logFilePaths.get(i), queue);
			tempWatcher.setToRun(true);
			this.watcherList.add(tempWatcher);
		}
		
		//create a thread for each log file watcher
		for(int i=0; i<this.watcherList.size(); i++){
			tempThread = new Thread(watcherList.get(i));
			this.watcherThreads.add(tempThread);
		}
		
		listener1 = new Client_ListenForAdminCommands(port, timeout, this);
		this.listenerThread = new Thread(this.listener1);
		
		this.logSenderThread = new Thread(this.logSender);
	}
	
	public void setAllWatcherSockets(String ip, int port){
		//if the ip passed in is empty or null, do nothing
		if(ip.isEmpty() || ip == null){
			return;
		}		
		//stop the threads before changing any of them
		stopAllWatchers();
		//System.out.println("Watcher list size: "+this.watcherList.size());
		
		this.logSender.setRunFlag(false);
		this.logSender.setSocketAddressAndPort(ip, port);
		this.logSender.setRunFlag(true);
		System.out.println("Log Sender Socket address and port set");
		
		System.out.println("Socket set. Starting watchers now.");
		//start the threads again
		startAllWatchers();
	}
	
	public void startAllWatchers(){
		
		//set them all to be able to run
		for(int i=0; i<this.watcherList.size(); i++){
			this.watcherList.get(i).setToRun(true);
		}
		//start all the threads if they aren't running
		for(int i=0; i<this.watcherThreads.size(); i++){
			if(!this.watcherThreads.get(i).isAlive()){
				this.watcherThreads.set(i, new Thread(this.watcherList.get(i)));
				this.watcherThreads.get(i).start();
			}
		}
		//wait until all threads are alive
		for(int i=0; i<this.watcherThreads.size(); i++){
			while(!this.watcherThreads.get(i).isAlive()){
				//wait
			}
			System.out.println("Waited for thread to start, now running");
		}
	}
	
	public void stopAllWatchers(){
		//tell all the watchers to stop
		for(int i=0; i<this.watcherList.size(); i++){
			this.watcherList.get(i).setToRun(false);
		}
		//wait for each thread to stop
		for(int i=0; i<this.watcherThreads.size(); i++){
			while(this.watcherThreads.get(i).isAlive()){
				//wait
			}
			System.out.println("Waited for thread to stop, Thread isnt running");
		}
	}
	
	public void startListener(){
		this.listenerThread.start();
	}
	
	public void startLogSender(){
		this.logSenderThread.start();
	}
	
	public File getLogFile(String logFileName){
		File f = null;
		boolean found = false;
		
		for(int i=0; i<this.watcherList.size(); i++){
			if(this.watcherList.get(i).getLogFileName().equals(logFileName)){
				found = true;
				f = this.watcherList.get(i).getLogFile();
			}
		}
		
		if(!found){
			System.out.println("File name not recognised. Filename: "+logFileName);
		}
		
		return f;
	}
	
	
	public static void main(String args[]){
		try {
			System.out.println("Starting Client Device");
			int port = 174;
			int timeout = 800;
			
			String directory = "/usr/local/var/log/suricata/";
			
			String file1 = directory+"dns.log";
			String file2 = directory+"drop.log";
			String file3 = directory+"fast.log";
			String file4 = directory+"http.log";
			String file5 = directory+"stats.log";
			
			List<String> logFiles = new ArrayList<String>();
			logFiles.add(file1);
			logFiles.add(file2);
			logFiles.add(file3);
			logFiles.add(file4);
			//logFiles.add(file5);
			
			Client_Device device = new Client_Device(logFiles, port, timeout);
			device.listener1.setClient_Device(device);
			device.startListener();
			System.out.println("Started Client Listener");
			device.startLogSender();
			System.out.println("Started Log Sender");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}