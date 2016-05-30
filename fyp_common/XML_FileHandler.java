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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XML_FileHandler {
	
	private String filepath;
	public final int Admin = 0;
	public final int notAdmin = 1;
	
	public XML_FileHandler(){
		this.filepath = null;
	}
	
	public void loadFile(String path){
		this.filepath = path;
	}
	
	//private method to check if the file that is loaded exists
	private boolean checkFileIsLegal(){
		if((this.filepath == null) || (!(new File(filepath).exists())) ){
			System.out.println("File path is not legal or file does not exist. Please load another file.");
			return false;
		}
		else{
			return true;
		}
	}
	
	//private method to return a document object for the xml file to edit
	private Document getDoc() throws ParserConfigurationException, SAXException, IOException{
		DocumentBuilderFactory DocBuilderFactory =  DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = DocBuilderFactory.newDocumentBuilder();
		Document document = docBuilder.parse(this.filepath);
		
		return document;
	}
	
	//private method to create a new transformer object to edit the existing xml file
	private Transformer getNewTransformer() throws TransformerConfigurationException{
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		
		return transformer;
	}
	
	public XML_Device getDevice(int isAdmin, String ipAddress) throws SAXException, IOException, ParserConfigurationException{
		
		if(!this.checkFileIsLegal()){
			return null;
		}
		
		if(isAdmin == Admin || isAdmin == notAdmin){
			Document doc = this.getDoc();
			
			//0 for an admin
			//1 not for an admin			
			switch(isAdmin){
			case(Admin):
				
				NodeList admin_devices = doc.getElementsByTagName("adminDevice");
				Node admin_device = admin_devices.item(0);
				
				if(admin_device.getNodeType() == Node.ELEMENT_NODE){
					Element e = (Element) admin_device;
					
					String ip = e.getElementsByTagName("ip").item(0).getTextContent();
					String hostname = e.getElementsByTagName("hostname").item(0).getTextContent();
					int port = Integer.parseInt(e.getElementsByTagName("port").item(0).getTextContent());
					String user = e.getElementsByTagName("user").item(0).getTextContent();
					String password = e.getElementsByTagName("password").item(0).getTextContent();
					
					XML_Device admin = new XML_Device(true, ip, hostname, port, user, password);
					return admin;					
				}
				else{					
					System.out.println("Admin Device in XML is not an element node");
					return null;
				}
			case(notAdmin):
				NodeList monitored_devices = doc.getElementsByTagName("device");
				
				for(int i=0; i<monitored_devices.getLength(); i++){
					if(monitored_devices.item(i).getNodeType() == Node.ELEMENT_NODE){
						Element e = (Element) monitored_devices.item(i);
						
						//if the given ip address matches the one from xml
						//return this device listed in the xml
						if(e.getElementsByTagName("ip").item(0).getTextContent().equals(ipAddress)){
							String ip = e.getElementsByTagName("ip").item(0).getTextContent();
							String hostname = e.getElementsByTagName("hostname").item(0).getTextContent();
							int port = Integer.parseInt(e.getElementsByTagName("port").item(0).getTextContent());
							String user = e.getElementsByTagName("user").item(0).getTextContent();
							String password = e.getElementsByTagName("password").item(0).getTextContent();
							
							XML_Device admin = new XML_Device(false, ip, hostname, port, user, password);
							return admin;
						}
					}
					else{						
						System.out.println("Not an element node");
					}
				}
				System.out.println("No matching IP address found");
				return null;
				
			default:
				System.out.println("Invalid option in case Statement");
				return null;
			}
		}
		else{
			System.out.println("Illegal option to determine isAdmin");
			return null;
		}
	}
	
	public List<XML_Device> getAllMonitoredDevices() throws SAXException, IOException, ParserConfigurationException{
		
		if(!this.checkFileIsLegal()){
			return null;
		}
		
		List<XML_Device> deviceList = new ArrayList<XML_Device>();
		
		Document doc = this.getDoc();
		
		NodeList monitored_devices = doc.getElementsByTagName("device");
		
		for(int i=0; i<monitored_devices.getLength(); i++){
			if(monitored_devices.item(i).getNodeType() == Node.ELEMENT_NODE){
				Element e = (Element) monitored_devices.item(i);
				
				String ip = e.getElementsByTagName("ip").item(0).getTextContent();
				String hostname = e.getElementsByTagName("hostname").item(0).getTextContent();
				int port = Integer.parseInt(e.getElementsByTagName("port").item(0).getTextContent());
				String user = e.getElementsByTagName("user").item(0).getTextContent();
				String password = e.getElementsByTagName("password").item(0).getTextContent();
				
				XML_Device deviceX = new XML_Device(false, ip, hostname, port, user, password);
				deviceList.add(deviceX);
				
			}
			else{						
				System.out.println("Not an element node");
			}
		}
		
		return deviceList;
	}

	public XML_Device getAdminDevice() throws SAXException, IOException, ParserConfigurationException{
		
		if(!this.checkFileIsLegal()){
			return null;
		}
		
		Document doc = this.getDoc();
		
		NodeList admin_devices = doc.getElementsByTagName("adminDevice");
		Node admin_device = admin_devices.item(0);
		
		if(admin_device.getNodeType() == Node.ELEMENT_NODE){
			Element e = (Element) admin_device;
			
			String ip = e.getElementsByTagName("ip").item(0).getTextContent();
			String hostname = e.getElementsByTagName("hostname").item(0).getTextContent();
			int port = Integer.parseInt(e.getElementsByTagName("port").item(0).getTextContent());
			String user = e.getElementsByTagName("user").item(0).getTextContent();
			String password = e.getElementsByTagName("password").item(0).getTextContent();
			
			XML_Device admin = new XML_Device(true, ip, hostname, port, user, password);
			return admin;
			
		}
		else{
			System.out.println("Admin Device in XML file is not formatted properly, ERROR!!!");
			return null;
		}		
	}
	
	public boolean removeMonitoredDevice(String ipAddress) throws SAXException, IOException, ParserConfigurationException, TransformerException{
		
		if(!this.checkFileIsLegal()){
			return false;
		}
		
		Document doc = this.getDoc();
		Element badNode = null;
		boolean removed = false;		
		NodeList monitored_devices = doc.getElementsByTagName("device");
		
		for(int i=0; i<monitored_devices.getLength(); i++){
			
			Node some_device = monitored_devices.item(i);
			
			if(some_device.getNodeType() == Node.ELEMENT_NODE){
				
				Element e = (Element)some_device;
				//if the node's ip matches the passed in ip
				if(e.getElementsByTagName("ip").item(0).getTextContent().equals(ipAddress)){
					badNode = e;
					break;
				}
			}
		}
		if(badNode != null){
			System.out.println("Bad node found");
			Node parent = badNode.getParentNode();
			parent.removeChild(badNode);
			
			Transformer transformer = this.getNewTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File(filepath));
			
			transformer.transform(source, result);
			
			removed = true;
		}
		else{
			System.out.println("No bad node found");
			removed = false;
		}
		
		return removed;
	}

	public boolean editMonitoredDevice(String ipAddress, XML_Device editedDevice) throws ParserConfigurationException, FileNotFoundException, SAXException, IOException, TransformerException{
		
		if(!this.checkFileIsLegal()){
			return false;
		}
		
		boolean edited = false;
		Element toBeEditedDevice = null;
		Document doc = this.getDoc();
		//get a list of devices being monitored
		NodeList monitored_devices = doc.getElementsByTagName("device");
		//loop through list of monitored devices
		for(int i=0; i<monitored_devices.getLength(); i++){
			
			Node some_device = monitored_devices.item(i);
			//check if the node is an element node
			if(some_device.getNodeType() == Node.ELEMENT_NODE){
				Element e = (Element)some_device;
				//if the node's ip matches the passed in ip
				if(e.getElementsByTagName("ip").item(0).getTextContent().equals(ipAddress)){
					toBeEditedDevice = e;
					break;
				}
			}
		}
		//if a matching element was found
		if(toBeEditedDevice != null){
			
			NodeList list = toBeEditedDevice.getChildNodes();
			Node n = null;
			String nodename = null;
			
			for(int i=0; i<list.getLength(); i++){
				n = list.item(i);
				nodename = n.getNodeName();
				
				switch(nodename){
				case("ip"):
					n.setTextContent(editedDevice.getIp());
					break;
				case("hostname"):
					n.setTextContent(editedDevice.getHostname());
					break;
				case("port"):
					n.setTextContent(String.valueOf(editedDevice.getPortNumber()));
					break;
				case("user"):
					n.setTextContent(editedDevice.getUsername());
					break;
				case("password"):
					n.setTextContent(editedDevice.getPassword());
					break;
				default:
					break;
				}
				
			}
			
			Transformer transformer = getNewTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File(filepath));
			
			transformer.transform(source, result);
			
			edited = true;
		}
		else{
			edited = false;
		}
		
		return edited;
	}
	
	public boolean addMonitoredDevice(XML_Device deviceToBeAdded) throws SAXException, IOException, ParserConfigurationException, TransformerException{
		
		if(!this.checkFileIsLegal()){
			return false;
		}
		
		XML_Device present = this.getDevice(notAdmin, deviceToBeAdded.getIp());
		
		if(present == null){
			
			System.out.println("boop");
			
			//open the xml file
			Document doc = this.getDoc();
			
			//get the monitored devices element
			NodeList monitored = doc.getElementsByTagName("monitoredDevices");
			Element monitoredDevicesElement = (Element) monitored.item(0);
			
			//create a new device tag and text
			Element newDevice = doc.createElement("device");
			//create a new ip tag and text
			Element ip = doc.createElement("ip");
			ip.appendChild(doc.createTextNode(deviceToBeAdded.getIp()));
			newDevice.appendChild(ip);
			//create a new hostname tag and text
			Element hostname = doc.createElement("hostname");
			hostname.appendChild(doc.createTextNode(deviceToBeAdded.getHostname()));
			newDevice.appendChild(hostname);
			//create a new port tag and text
			Element port = doc.createElement("port");
			port.appendChild(doc.createTextNode(String.valueOf(deviceToBeAdded.getPortNumber())));
			newDevice.appendChild(port);
			//create a new user tag and text
			Element user = doc.createElement("user");
			user.appendChild(doc.createTextNode(deviceToBeAdded.getUsername()));
			newDevice.appendChild(user);
			//create a new password tag and text
			Element password = doc.createElement("password");
			password.appendChild(doc.createTextNode(deviceToBeAdded.getPassword()));
			newDevice.appendChild(password);
			//add the new element to the parent
			monitoredDevicesElement.appendChild(newDevice);
			
			Transformer transformer = getNewTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File(filepath));
			
			transformer.transform(source, result);
			
			return true;
		}
		else{
			System.out.println("IP Address is already being monitored, cannot add to watch list");
			return false;
		}
	}	
}