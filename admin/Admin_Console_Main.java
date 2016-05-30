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
import javax.swing.JFrame;

public class Admin_Console_Main {
	
	
	public static void main(String[] args){
		LaunchGUI();
	}
	
	public static void LaunchGUI(){
		int timeout = 800;
		int port = 174;
		
		String downloadDir = "C:\\Users\\Kyle\\Downloads";
		//String downloadDir = "D:\\Downloads";
		
		//String xmlFilePath = "D:\\My Documents\\4th year uni\\FYP\\DeviceList.xml";
		String xmlFilePath = "C:\\Users\\Kyle\\Documents\\4th year uni\\FYP\\DeviceList.xml";
		
		
		Admin_GUI_Console application = new Admin_GUI_Console(xmlFilePath);
		application.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		application.loadXML_Device_File(xmlFilePath);
		
		application.writeToUpdateBox("This device is Listening on port: "+port);
		
		Admin_ListenForClients listener = new Admin_ListenForClients(port, timeout, application, downloadDir);
		listener.loadXMLFile(xmlFilePath);
		Thread t = new Thread(listener);
		t.start();
		
		Admin_TalkToClients talker;
		try {
			talker = new Admin_TalkToClients(port, "");

			application.loadTalker(talker);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
