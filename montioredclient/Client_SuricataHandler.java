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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class Client_SuricataHandler {
	//class to handle controlling Suricata and it's rule files and suricata.yaml file	
	private final String sudo = "sudo ";
	private final String suricata = "suricata ";
	private final String configFlag = "-c ";
	
	//private final String configFilePath_win = "C:\\Users\\Kyle\\Documents\\4th year uni\\FYP\\Suricata config\\suricata.yaml";
	private final String configFilePath_linux = "/usr/local/etc/suricata/suricata.yaml";
	//god help us if anyone moves this bloody .yaml file ^
	
	//private final String config_FilePath_win_testDummy = "C:\\Users\\Kyle\\Documents\\4th year uni\\FYP\\Suricata config\\suricata2.yaml";
	private final String config_FilePath_linux_testDummy = "/usr/local/etc/suricata/suricata2.yaml";
	
	private final String interfaceCard = " -i ";
	private String interfaceCardName;
	private final String conditions = " --init-errors-fatal";
	
	final String ruleFormat = " - ";
	final String ruleCommentedformat = "# - ";
	
	final String remove = "rm ";
	final String rulefiles = "rule-files:";
	final String actionOrder = "action-order:";
	
	private Process suricataProcess;
	private Enumeration<NetworkInterface> ni;	
	private String rulesDefaultLocation;	
	//sudo suricata -c /etc/suricata/suricata.yaml -i wlan0 --init-errors-fatal
	
	
	//public constructor
	public Client_SuricataHandler(){

		try {
			this.ni = NetworkInterface.getNetworkInterfaces();			
		} catch (SocketException e) {
			e.printStackTrace();
		}
		this.interfaceCardName = this.getInterfaceName();
		this.rulesDefaultLocation = "";
		
	}
	
	//public method to restart Suricata
	public void restartSuricataEngine(){
		//stop Suricata
		this.stopSuricataEngine();
		//start Suricata
		this.startSuricataEngine();
	}
	
	//public method to start Suricata
	public void startSuricataEngine(){
		System.out.println("Starting the engine in suricata handler");
		this.suricataProcess = this.startSuricata();
	}
	
	//public method to stop Suricata
	public void stopSuricataEngine(){
		this.stopSuricata();
		this.suricataProcess = null;
	}
	
	//public method to check if the name of a rule file is being used
	public boolean isRuleFileUsed(String filename){
		boolean f = false;
		//no empty string please
		if(filename.isEmpty()){
			return false;
		}
		
		List<String> rulefiles = this.getAllRuleFileNames();
		if(rulefiles.contains(filename)){
			//f = new File(this.getRulesDefaultLocation()+"\\"+filename);
			f = true;
		}
		
		return f;
	}
	
	//public method to get a rule file
	public File getRuleFile(String ruleFileName){
		File f = null;
		
		if(this.isRuleFileUsed(ruleFileName)){
			f = new File(this.getRulesDefaultLocation()+"/"+ruleFileName);
		}
		
		return f;
	}
	
	//public method to get allRuleFiles
	public List<File> getAllRuleFiles(){
		List<File> ruleFileList = new ArrayList<File>();
		List<String> ruleFileNames = this.getAllRuleFileNames();
		String defaultLocation = this.getRulesDefaultLocation();
		
		//add all the rule files to the list
		for(int i=0; i<ruleFileNames.size(); i++){
			ruleFileList.add(new File(defaultLocation+"/"+ruleFileNames.get(i)));
		}
		
		return ruleFileList;
	}
	
	//method to check if a rule file is being used in the suricata config file
	//and if so to remove the listing and delete the file from the device
	public boolean removeRuleFile(String filename){
		boolean b = this.isRuleFileUsed(filename);
		
		if(b == true){
			try{
				deleteFile(this.getRulesDefaultLocation()+"/"+filename);
				removeRuleFileFromConfigFile(filename);
				return true;
			}
			catch(Exception e){
				e.printStackTrace();
				return false;
			}			
		}
		else{
			return false;
		}
	}
	
	//public method to create a new rule file and add it to the config file
	public boolean createNewRuleFile(String ruleFileName, String ruleFileText){
		boolean b = false;
		
		try{
			//create a new file
			//System.out.println("Absolute filepath= "+this.getRulesDefaultLocation()+"/"+ruleFileName);
			File f = new File(this.getRulesDefaultLocation()+"/"+ruleFileName);
			
			f.createNewFile();
			
			this.writeFile((this.getRulesDefaultLocation()+"/"+ruleFileName), ruleFileText);
			this.addRuleFileToConfigFile(ruleFileName);
			b = true;
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
		return b;
	}
	
	//public method to change action order based off of numbers
	public boolean changeActionOrder(List<Integer> actionOrder){
		boolean b = false;
		List<String> actionOrderStrings = new ArrayList<String>();
		String pass = "  - pass\n";
		String drop = "  - drop\n";
		String reject = "  - reject\n";
		String alert = "  - alert\n";
		
		for(int i=0; i<actionOrder.size(); i++){
			switch(actionOrder.get(i)){
			case(1):
				if(!actionOrderStrings.contains(pass)){
					actionOrderStrings.add(pass);
				}
				break;
			case(2):
				if(!actionOrderStrings.contains(drop)){
					actionOrderStrings.add(drop);
				}
				break;
			case(3):
				if(!actionOrderStrings.contains(reject)){
					actionOrderStrings.add(reject);
				}
				break;
			case(4):
				if(!actionOrderStrings.contains(alert)){
					actionOrderStrings.add(alert);
				}
				break;
			default:
				break;			
			}
		}
		if(actionOrderStrings.size() == 4){			
			try{
				changeActionOrderInYaml(actionOrderStrings);
				b = true;
			}
			catch(Exception e){
				e.printStackTrace();
			}
		}		
		return b;
	}
	
	//public method to change the contents of a rule file being used
	public boolean editRuleFile(String ruleFileName, String ruleFileText){
		boolean b = false;
		
		if(this.isRuleFileUsed(ruleFileName)){			
			try {
				this.clearFile(this.getRulesDefaultLocation()+"/"+ruleFileName);
				this.writeFile((this.getRulesDefaultLocation()+"/"+ruleFileName), ruleFileText);
				b = true;
			} 
			catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		return b;
	}
	
	//private method to get the rules location from the config file
	private String getRulesDefaultLocation(){
		String s = null;
		//if we loaded the rule location already, return it
		if(!rulesDefaultLocation.isEmpty()){
			return this.rulesDefaultLocation;
		}
		try {
	        BufferedReader br = new BufferedReader(new FileReader(this.configFilePath_linux));
	        String line = "";
	        while ((line = br.readLine()) != null) {
	        	try{
	        		if(line.contains("default-rule-path:")){
	        			s = ""+line.replace("default-rule-path: ", "");
		    	        this.rulesDefaultLocation = s;
	        		}	        		
	        	}
	        	catch(Exception e){
	        		//catch any problems reading yaml file cause of it's erratic structure
	        	}
	        }
	        br.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return s;
	}
	
	//private method to get a list of all file names
	private List<String> getAllRuleFileNames(){
		List<String> names = new ArrayList<String>();		
		
		try {
	        BufferedReader br = new BufferedReader(new FileReader(this.configFilePath_linux));
	        String line = "";
	        while ((line = br.readLine()) != null) {
	        	try{
	        		if(line.equals(rulefiles)){
	        			
	        			while((line = br.readLine()) != null){
	        				line = this.checkToAddLineToRuleFileList(line);
	        				
	        				if(line.equals("no")){
	        					//do nothing
	        				}
	        				else if(!line.isEmpty() && !line.equals("stop")){	        					
	        					names.add(line);
	        				}
	        				else if(line.equals("stop")){
	        					break;
	        				}
	        			}//end of inner while
	        			
	        			break;
	        		}
	        	}
	        	catch(Exception e){
	        		e.printStackTrace();
	        		//catch any problems reading yaml file cause of it's erratic structure
	        	}
	            
	        }//end of outer while
	        br.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		return names;
	}
	
	//private method to get the interface card name
	private String getInterfaceName(){
		while (ni.hasMoreElements())
		{
		    NetworkInterface networkInterface = (NetworkInterface) ni.nextElement();
		    return networkInterface.getDisplayName();
		}
		return null;
	}
	
	//private method to check if a rule file is commented out or being used
	private String checkToAddLineToRuleFileList(String line){
		String temp = null;
		String temps[] = null;
		final String format = " - ";
		final String commentedformat = "# - ";
		
		if(line.contains(commentedformat)){
			temp = "no";
		}
		else if(line.contains(format)){
			temps = line.split("#");//remove any comments on the end			
			temp = temps[0].replace(format, "");//remove the ' - ' from the line
		}
		else{
			temp = "stop";
		}
		
		return temp;
	}
	
	//private method to forcefully stop Suricata
	private void stopSuricata(){
		if(this.suricataProcess != null){
			this.suricataProcess.destroy();
		}
	}
	
	//private method to start a new Suricata process
	private Process startSuricata(){
		//if the process object isn't empty, return the running process
		if(this.suricataProcess != null){
			System.out.println("Engine already running");
			return this.suricataProcess;
		}
		//create the linux command to run it
		String runSuricata = this.sudo+this.suricata+this.configFlag+this.configFilePath_linux+
							 this.interfaceCard+this.interfaceCardName+conditions;
		//create the process to run the engine
		Process p =null;
		try {
			System.out.println("Creating process to run engine");
			System.out.println(runSuricata);
			p = Runtime.getRuntime().exec(runSuricata);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return p;
	}
	
	//private method to delete a file on the local device
	private void deleteFile(String filepath) throws NullPointerException{ 
		
		File f = new File(filepath);
		f.delete();
	}
	
	//private method to add a rule file to the list insode the config file
	private void addRuleFileToConfigFile(String filename){
		try {
			File originalFileHolder = new File(this.configFilePath_linux);
			File editedFileHolder = new File(this.config_FilePath_linux_testDummy);
			String currentline = "";
			String listedFile = this.ruleFormat+filename;
			
			BufferedReader reader = new BufferedReader(new FileReader(originalFileHolder));
			PrintWriter writer = new PrintWriter(new FileWriter(editedFileHolder));
			
			//write the entire file to a temporary file
			while((currentline = reader.readLine()) != null){
				writer.println(currentline);
				writer.flush();
				
				//if we just wrote in the map key for rule files
			if(currentline.equals(this.rulefiles)){
				//add the rule file to the config file
					writer.println(listedFile);
					writer.flush();
				}
				
			}
			System.out.println(listedFile);
			reader.close();
			writer.close();
			
			//Delete the original file
			if(!originalFileHolder.delete()) {
			  System.out.println("Could not delete file");
			} 
			  
			//Rename the new file to the filename the original file had.
			if(!editedFileHolder.renameTo(originalFileHolder)){
				System.out.println("Could not rename file");
			} 
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//private method to remove a rule from the config file
	private void removeRuleFileFromConfigFile(String filename){
		try {
			File originalFileHolder = new File(this.configFilePath_linux);
			File editedFileHolder = new File(this.config_FilePath_linux_testDummy);
			String currentline = "";
			String listedFile = this.ruleFormat+filename;
			
			BufferedReader reader = new BufferedReader(new FileReader(originalFileHolder));
		    PrintWriter writer = new PrintWriter(new FileWriter(editedFileHolder));
			
			while((currentline = reader.readLine()) != null){
				
				if(!currentline.equals(listedFile)){
					writer.println(currentline);
					writer.flush();
				}
				else{
					System.out.println("found the line: "+currentline);
				}
			}
			System.out.println(listedFile);
			reader.close();
			writer.close();
			
			//Delete the original file
		      if (!originalFileHolder.delete()) {
		        System.out.println("Could not delete file");
		      } 
		      
		      //Rename the new file to the filename the original file had.
		      if (!editedFileHolder.renameTo(originalFileHolder)){
		    	  System.out.println("Could not rename file");
		      }
		        
		}
		catch (Exception e) {
			e.printStackTrace();
		}		
	}
	
	//private method to clear an entire file without deleting it
	private void clearFile(String filePath) throws FileNotFoundException{
		PrintWriter pw = new PrintWriter(new File(filePath));
		pw.write("");
		pw.close();		
	}
	
	//private method to write text to a file
	private void writeFile(String filePath, String allFileText) throws FileNotFoundException{
		PrintWriter pw = new PrintWriter(new File(filePath));
		pw.write(allFileText);
		pw.close();
	}

	//private method to change the order of action in the config file
	private void changeActionOrderInYaml(List<String> order){
		try {
			File originalFileHolder = new File(this.configFilePath_linux);
			File editedFileHolder = new File(this.config_FilePath_linux_testDummy);
			String currentline = "";
			
			BufferedReader reader = new BufferedReader(new FileReader(originalFileHolder));
			PrintWriter writer = new PrintWriter(new FileWriter(editedFileHolder));
			
			//write the entire file to a temporary file
			while((currentline = reader.readLine()) != null){
				writer.println(currentline);
				writer.flush();
				
				//if we just wrote in the map key for rule files
				if(currentline.equals(this.actionOrder)){
				//add the rule file to the config file
					for(int i=0; i<order.size(); i++){
						//write the action order as passed in
						writer.write(order.get(i));
						writer.flush();
						//need to skip over the lines we're writing
						currentline = reader.readLine();
					}
				}
				
			}
			reader.close();
			writer.close();
			
			//Delete the original file
			if(!originalFileHolder.delete()) {
			  System.out.println("Could not delete file");
			} 
			  
			//Rename the new file to the filename the original file had.
			if(!editedFileHolder.renameTo(originalFileHolder)){
				System.out.println("Could not rename file");
			} 
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
