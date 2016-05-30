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

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.xml.sax.SAXException;
import fyp_common.XML_Device;
import fyp_common.XML_FileHandler;

public class Admin_GUI_Console extends JFrame {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private final String str_SourceIP="Source IP", str_SourcePort="Source Port", 
						 str_RuleMsg="Rule Message", str_RuleSigID="Rule Signature ID", 
						 str_TTL="Time to Live", str_PacketContent="Packet Content",
						 str_DestinationIP="Destination IP", str_DestinationPort="Destination Port", 
						 str_RuleClassType="Rule class type", str_RuleRevisionID="Rule Revision ID", 
						 str_SameIP="Same IP (leave empty if no)", str_Rulename="Rulename (include '.rules' extension)",
						 str_OriginalRuleName="Original Rulename (include '.rules')";
	
	//-- components for new rule file tab --//
	private JRadioButton tcpButton, udpButton, icmpButton, httpButton, ftpButton, tlsButton, smbButton, dnsButton, ipButton;	
	private String protocolChoice = "tcp";	
	private JRadioButton passButton, alertButton, dropButton, rejectButton;
	private String actionChoice = "alert";	
	private ButtonGroup protocolGroup, actionGroup;
	private JButton createRuleButton, createRuleResetButton;
	private JTextField sourceIpTextField, destinationIpTextField, sourcePortTextField, destinationPortTextField, messageTextField, classtypeTextField, signatureIdTextField, revisionIdTextField, timeToLiveTextField, sameIpTextField, ruleNameTextField;
	private JTextArea contentTextBox;
	
	//contentTextBox ruleNameTextField
	
	//-- components for edit rule file tab--//
	private JRadioButton editRule_tcpButton, editRule_udpButton, editRule_icmpButton, editRule_httpButton, editRule_ftpButton, editRule_tlsButton, editRule_smbButton, editRule_dnsButton, editRule_ipButton;	
	private String editRule_protocolChoice = "tcp";	
	private JRadioButton editRule_passButton, editRule_alertButton, editRule_dropButton, editRule_rejectButton;
	private String editRule_actionChoice = "alert";	
	private ButtonGroup editRule_protocolGroup, editRule_actionGroup;
	private JButton editRule_createRuleButton, editRule_createRuleResetButton;
	private JTextField editRule_sourceIpTextField, editRule_destinationIpTextField, editRule_sourcePortTextField, editRule_destinationPortTextField, editRule_messageTextField, editRule_classtypeTextField, editRule_signatureIdTextField, editRule_revisionIdTextField, editRule_timeToLiveTextField, editRule_sameIpTextField, editRule_originalRuleNameTextField;
	private JTextArea editRule_contentTextBox;
	
	//components for suricatacontrol tab
	private JButton suricataControl_Start, suricataControl_Stop, suricataControl_Restart;
	
	//components for watcher controls tab
	private JButton watcherControl_StopWatchersButton, watcherControl_StartWatchersButton, watcherControl_RestartWatchersButton, watcherControl_SetWatchersButton;
	private JTextField watcherControl_IpAddress, watcherControl_Port;
	
	//components for monitored devices tab
	private JButton deviceManager_AddDevice, deviceManager_RemoveDevice;
	private JTextField deviceManager_Ip, deviceManager_HostName, deviceManager_Port, deviceManager_UserName, deviceManager_Password, deviceManager_PasswordConfirm;
	
	//components for suricata file handler tab
	private JButton suricataFileHandler_GetRule, suricataFileHandler_GetAllRules, suricataFileHandler_GetLogFile, suricataFileHandler_DeleteRule, suricataFileHandler_ChangeActionOrder;
	private JTextField suricataFileHandler_RuleName, suricataFileHandler_LogName, suricataFileHandler_RuleToBeDeleted;
	private JComboBox<String> firstActionCB, secondActionCB, thirdActionCB, fourthActionCB;
	private final String[] actionCB_Strings = {"pass", "drop", "reject", "alert"};
	
	//-- components for the whole GUI --//
	private ButtonGroup deviceGroup;
	private ArrayList<JRadioButton> deviceRadioButtonList;
	private String deviceChoice;
	private JTextArea updateBox, clientUpdateBox;
	private JTabbedPane tabbedpane;
	private JPanel addNewRulePanel, editRulePanel, watcherControlPanel, suricataControlPanel, suricataFilePanel, deviceManagerPanel;
	private Container rootContainer;
	private JPanel CentrePanel, LeftPanel, RightPanel, BottomPanel;
	
	private final int tabPanelWidth = 600, tabPanelHeight = 300;
	private final int guiWidth = 1000, guiHeight = 500;
	private Admin_TalkToClients talker;
	private XML_FileHandler xmlHandler;
	
	// set up GUI
	public Admin_GUI_Console(String xmlDeviceFilePath) {
		super("Admin Console for managing monitored Suricata Devices");
		this.loadXML_Device_File(xmlDeviceFilePath);
		// get content pane and set its layout
		this.rootContainer = getContentPane();
		GridBagLayout layout = new GridBagLayout();
		this.rootContainer.setLayout(layout);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.gridy = 0;
		
		//initialize the 4 main panels
		this.LeftPanel = new JPanel();		
		this.RightPanel = new JPanel();
		this.CentrePanel = new JPanel();
		this.BottomPanel = new JPanel();
		
		//initialize the control tabs
		this.tabbedpane = new JTabbedPane();
		this.addNewRulePanel = this.createNewRuleTab();		
		this.editRulePanel = this.createEditRuleTab();
		this.watcherControlPanel = this.createWatcherControlTab();
		this.suricataControlPanel = this.createSuricataControlTab();
		this.suricataFilePanel = this.createSuricataFileTab();
		this.deviceManagerPanel = this.createDeviceManagerTab();
		
		//add the tabs to the tabbed pane
		this.tabbedpane.addTab("Add a new rule to a device", this.addNewRulePanel);
		this.tabbedpane.addTab("Edit a rule on a device", this.editRulePanel);
		this.tabbedpane.addTab("Control the file watchers on a device", this.watcherControlPanel);
		this.tabbedpane.addTab("Control Suricata on a device", this.suricataControlPanel);
		this.tabbedpane.addTab("Control the files on Suricata", this.suricataFilePanel);
		this.tabbedpane.addTab("Manage devices being monitored", this.deviceManagerPanel);
		
		//set constraints for panel and add to the main container
		layout.setConstraints(this.CentrePanel, gbc);
		this.CentrePanel.add(this.tabbedpane);
		//add a black border around the panel
		this.CentrePanel.setBorder(BorderFactory.createLineBorder(Color.black));
		gbc.gridx=1;
		gbc.gridy=0;
		this.rootContainer.add(this.CentrePanel);
		
		//set constraints for panel and add to the main container
		this.LeftPanel = setupLeftDevicePanel();
		//add a black border around the panel
		this.LeftPanel.setBorder(BorderFactory.createLineBorder(Color.black));
		gbc.gridx=0;
		gbc.gridy=0;
		layout.setConstraints(this.LeftPanel, gbc);
		this.rootContainer.add(this.LeftPanel);
		
		//set constraints for panel and add to the main container
		this.BottomPanel = this.setupBottomPanel();
		//add a black border around the panel
		this.BottomPanel.setBorder(BorderFactory.createLineBorder(Color.black));
		gbc.gridx=1;
		gbc.gridy=1;
		layout.setConstraints(this.BottomPanel, gbc);
		this.rootContainer.add(this.BottomPanel);
		
		//set constraints for panel and add to the main container
		this.RightPanel = this.setupRightPanel();
		//add a black border around the panel
		this.RightPanel.setBorder(BorderFactory.createLineBorder(Color.black));
		gbc.gridx=2;
		gbc.gridy=0;
		layout.setConstraints(this.RightPanel, gbc);
		this.rootContainer.add(this.RightPanel);
		
		//set size of JFrame app window
		setSize(this.guiWidth, this.guiHeight);
		setVisible(true);
	}
	
	//private method to set up the log updates panel
	private JPanel setupRightPanel(){
		//create a new panel and constraints with a layout
		JPanel jp = new JPanel();
		GridBagLayout layout = new GridBagLayout();
		jp.setLayout(layout);
		GridBagConstraints gbc = new GridBagConstraints();
		
		//initialize component with constraints and add it to the panel
		this.clientUpdateBox = new JTextArea(20, 20);
		this.clientUpdateBox.setEditable(false);
		this.clientUpdateBox.setLineWrap(true);
		gbc.gridx=0;
		gbc.gridy=0;
		layout.setConstraints(this.clientUpdateBox, gbc);
		jp.add(new JScrollPane(this.clientUpdateBox));
		
		//return panel
		return jp;
	}
	
	//private method to create the command log panel
	private JPanel setupBottomPanel(){
		//initialize panel and set a layout scheme and and create constraints
		JPanel jp = new JPanel();
		GridBagLayout layout = new GridBagLayout();
		jp.setLayout(layout);
		GridBagConstraints gbc = new GridBagConstraints();
		
		//initialize the command log text area and make it un-editable
		this.updateBox = new JTextArea(7, 25);
		this.updateBox.setEditable(false);
		this.updateBox.setLineWrap(true);
		gbc.gridx=0;
		gbc.gridy=0;
		//set constraints and add it to the panel
		layout.setConstraints(this.updateBox, gbc);
		jp.add(new JScrollPane(this.updateBox));
		
		//return the panel
		return jp;
	}

	//private method to create the radio Suricata host button panel
	private JPanel setupLeftDevicePanel(){
		JPanel jp = new JPanel();
		GridBagLayout layout = new GridBagLayout();
		jp.setLayout(layout);
		GridBagConstraints gbc = new GridBagConstraints();
		
		
		if(this.xmlHandler == null){
			return jp;
		}
		else{
			//if the xml handler is not null
			//create a new button group and arraylist of buttons
			this.deviceGroup = new ButtonGroup();
			this.deviceRadioButtonList = new ArrayList<JRadioButton>();
			
			List<XML_Device> devices = null;
			try {
				//get all the listed devices
				devices = this.xmlHandler.getAllMonitoredDevices();
				//make a radio button for each device
				for(XML_Device d : devices){
					JRadioButton jrb = new JRadioButton(d.getHostname());
					jrb.setSelected(false);
					jrb.addActionListener(new DeviceSelectRadioButtonHandler());
					
					this.deviceRadioButtonList.add(jrb);
					this.deviceGroup.add(jrb);
				}
				
			} catch (SAXException | IOException | ParserConfigurationException e) {
				e.printStackTrace();
			}
			gbc.gridx = 0;
			for(int i=0; i<this.deviceRadioButtonList.size(); i++){
				//set each buttons position and add to the panel
				gbc.gridy = i;
				layout.setConstraints(this.deviceRadioButtonList.get(i), gbc);
				jp.add(this.deviceRadioButtonList.get(i));
			}
		}
		//return the panel
		return jp;
	}
	
	//public method to write to the command log Text area
	public void writeToUpdateBox(String update){
		if(this.updateBox != null){
			this.updateBox.append("\n"+update);
		}
	}
	
	//public method to write to the Suricata log update box
	public void writeToClientUpdateBox(String update){
		if(this.clientUpdateBox != null){
			this.clientUpdateBox.append("\n\n"+update);
		}
	}
	
	//private method to reinitailize all the radio buttons when a new one is added or one is removed
	private void reinitializeDeviceRadioButtons(){
		
		if(this.xmlHandler == null){
			return;
		}
		
		//remove the old radio buttons
		Container container = this.LeftPanel;
		GridBagLayout layout = (GridBagLayout) this.LeftPanel.getLayout();
		if(this.deviceRadioButtonList != null){
			for(JRadioButton j : this.deviceRadioButtonList){
				container.remove(j);
			}
		}
		System.out.println("Reinitialising Radio Buttons");
		
		//create a fresh group and list of radio buttons
		this.deviceGroup = new ButtonGroup();
		this.deviceRadioButtonList = new ArrayList<JRadioButton>();
		
		List<XML_Device> devices = null;
		try {
			//get all the listed devices
			devices = this.xmlHandler.getAllMonitoredDevices();
			//make a radio button for each device
			for(XML_Device d : devices){
				JRadioButton jrb = new JRadioButton(d.getHostname());
				jrb.setSelected(false);
				jrb.addActionListener(new DeviceSelectRadioButtonHandler());
				
				this.deviceRadioButtonList.add(jrb);
				this.deviceGroup.add(jrb);
			}
			
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
		}
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		for(int i=0; i<this.deviceRadioButtonList.size(); i++){
			//set the position of each radio button
			gbc.gridy = i;
			layout.setConstraints(this.deviceRadioButtonList.get(i), gbc);
			this.LeftPanel.add(this.deviceRadioButtonList.get(i));
		}
		
	}
	
	//public method to load an xml file into the xmlFile_Handler object
	public void loadXML_Device_File(String filepath){
		this.xmlHandler = new XML_FileHandler();
		this.xmlHandler.loadFile(filepath);
	}
	
	//public method to load a talker object to the GUI
	public void loadTalker(Admin_TalkToClients attc){
		this.talker = attc;
	}

	//-- private methods for creating the tabs --//
	
	//private method to create the new rule tab
 	private JPanel createNewRuleTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);
		
		this.sourceIpTextField = new JTextField(this.str_SourceIP, 20);
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.sourceIpTextField, constraints );
		jp.add( this.sourceIpTextField );
		this.destinationIpTextField = new JTextField(this.str_DestinationIP, 20);
		constraints.gridx = 1;
		constraints.gridy = 0;
		gbl.setConstraints( this.destinationIpTextField, constraints );
		jp.add( this.destinationIpTextField );
		this.sourcePortTextField = new JTextField(this.str_SourcePort, 20);
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.sourcePortTextField, constraints );
		jp.add( this.sourcePortTextField );
		this.destinationPortTextField = new JTextField(this.str_DestinationPort, 20);
		constraints.gridx = 1;
		constraints.gridy = 1;
		gbl.setConstraints( this.destinationPortTextField, constraints );
		jp.add( this.destinationPortTextField );
		this.messageTextField = new JTextField(this.str_RuleMsg, 20);
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.messageTextField, constraints );
		jp.add( this.messageTextField );
		this.classtypeTextField = new JTextField(this.str_RuleClassType, 20);
		constraints.gridx = 1;
		constraints.gridy = 2;
		gbl.setConstraints( this.classtypeTextField, constraints );
		//jp.add( this.classtypeTextField );
		this.signatureIdTextField = new JTextField(this.str_RuleSigID, 20);
		constraints.gridx = 0;
		constraints.gridy = 3;
		gbl.setConstraints( this.signatureIdTextField, constraints );
		jp.add( this.signatureIdTextField );
		this.revisionIdTextField = new JTextField(this.str_RuleRevisionID, 20);
		constraints.gridx = 1;
		constraints.gridy = 3;
		gbl.setConstraints( this.revisionIdTextField, constraints );
		jp.add( this.revisionIdTextField );
		this.timeToLiveTextField = new JTextField(this.str_TTL, 20);
		constraints.gridx = 0;
		constraints.gridy = 4;
		gbl.setConstraints( this.timeToLiveTextField, constraints );
		jp.add( this.timeToLiveTextField );
		this.sameIpTextField = new JTextField(this.str_SameIP, 20);
		constraints.gridx = 1;
		constraints.gridy = 4;
		gbl.setConstraints( this.sameIpTextField, constraints );
		jp.add( this.sameIpTextField );
		
		//-- Create radio button group for protocol --//
		this.tcpButton = new JRadioButton( "Tcp", true );
		this.tcpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 0;
		gbl.setConstraints( this.tcpButton, constraints );
		jp.add( this.tcpButton );
		this.udpButton = new JRadioButton( "Udp", false );
		this.udpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 1;
		gbl.setConstraints( this.udpButton, constraints );
		jp.add( this.udpButton );
		this.icmpButton = new JRadioButton( "Icmp", false );
		this.icmpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 2;
		gbl.setConstraints( this.icmpButton, constraints );
		jp.add( this.icmpButton );
		this.httpButton = new JRadioButton( "Http", false );
		this.httpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 3;
		gbl.setConstraints( this.httpButton, constraints );
		jp.add( this.httpButton );
		this.ftpButton = new JRadioButton( "Ftp", false );
		this.ftpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 4;
		gbl.setConstraints( this.ftpButton, constraints );
		jp.add( this.ftpButton );
		this.tlsButton = new JRadioButton( "Tls", false );
		this.tlsButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 5;
		gbl.setConstraints( this.tlsButton, constraints );
		jp.add( this.tlsButton );
		this.smbButton = new JRadioButton( "Smb", false );
		this.smbButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 6;
		gbl.setConstraints( this.smbButton, constraints );
		jp.add( this.smbButton );
		this.dnsButton = new JRadioButton( "Dns", false );
		this.dnsButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 7;
		gbl.setConstraints( this.dnsButton, constraints );
		jp.add( this.dnsButton );
		this.ipButton = new JRadioButton( "Any protocol", false );
		this.ipButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 8;
		gbl.setConstraints( this.ipButton, constraints );
		jp.add( this.ipButton );
				
		CreateRuleProtocolRadioButtonHandler protocolHandler = new CreateRuleProtocolRadioButtonHandler();
		this.tcpButton.addActionListener(protocolHandler);
		this.udpButton.addActionListener(protocolHandler);
		this.icmpButton.addActionListener(protocolHandler);
		this.httpButton.addActionListener(protocolHandler);
		this.ftpButton.addActionListener(protocolHandler);
		this.tlsButton.addActionListener(protocolHandler);
		this.smbButton.addActionListener(protocolHandler);
		this.dnsButton.addActionListener(protocolHandler);
		this.ipButton.addActionListener(protocolHandler);
				
		this.protocolGroup = new ButtonGroup();
		this.protocolGroup.add(this.tcpButton);
		this.protocolGroup.add(this.udpButton);
		this.protocolGroup.add(this.icmpButton);
		this.protocolGroup.add(this.httpButton);
		this.protocolGroup.add(this.ftpButton);
		this.protocolGroup.add(this.tlsButton);
		this.protocolGroup.add(this.smbButton);
		this.protocolGroup.add(this.dnsButton);
		this.protocolGroup.add(this.ipButton);
		
		//-- Create radio buttons for action --//
		this.alertButton = new JRadioButton("Alert", true);
		constraints.gridx = 3;
		constraints.gridy = 0;
		gbl.setConstraints( this.alertButton, constraints );
		jp.add(this.alertButton);	
		this.passButton = new JRadioButton("Pass" , false);
		constraints.gridx = 3;
		constraints.gridy = 1;
		gbl.setConstraints( this.passButton, constraints );
		jp.add(this.passButton);	
		this.rejectButton = new JRadioButton("Reject", false);
		constraints.gridx = 3;
		constraints.gridy = 2;
		gbl.setConstraints( this.rejectButton, constraints );
		jp.add(this.rejectButton);	
		this.dropButton = new JRadioButton("Drop", false);
		constraints.gridx = 3;
		constraints.gridy = 3;
		gbl.setConstraints( this.dropButton, constraints );
		jp.add(this.dropButton);
		
		CreateRuleActionRadioButtonHandler actionHandler = new CreateRuleActionRadioButtonHandler();
		this.alertButton.addActionListener(actionHandler);
		this.passButton.addActionListener(actionHandler);
		this.rejectButton.addActionListener(actionHandler);
		this.dropButton.addActionListener(actionHandler);
		
		this.actionGroup = new ButtonGroup();
		this.actionGroup.add(this.alertButton);
		this.actionGroup.add(this.passButton);
		this.actionGroup.add(this.rejectButton);
		this.actionGroup.add(this.dropButton);
		
		this.contentTextBox = new JTextArea(this.str_PacketContent, 4, 20);
		constraints.gridx=0;
		constraints.gridy=5;
		gbl.setConstraints(this.contentTextBox, constraints);
		jp.add(this.contentTextBox);
		
		this.ruleNameTextField = new JTextField(this.str_Rulename, 20);
		constraints.gridx=1;
		constraints.gridy=5;
		gbl.setConstraints(this.ruleNameTextField, constraints);
		jp.add(this.ruleNameTextField);
		
		this.createRuleButton = new JButton("Create new rule");
		constraints.gridx = 0;
		constraints.gridy = 6;
		gbl.setConstraints( this.createRuleButton, constraints );
		jp.add(this.createRuleButton);	
		this.createRuleResetButton = new JButton("Reset rule parameters");
		constraints.gridx = 1;
		constraints.gridy = 6;
		gbl.setConstraints( this.createRuleResetButton, constraints );
		jp.add(this.createRuleResetButton);	
		CreateRuleButtonHandler bHandler = new CreateRuleButtonHandler();
		this.createRuleButton.addActionListener(bHandler);
		CreateRuleResetButtonHandler resetHandler = new CreateRuleResetButtonHandler();
		this.createRuleResetButton.addActionListener(resetHandler);
		
		return jp;
	}
	
 	//private method to create the edit rule tab
	private JPanel createEditRuleTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);
		
		this.editRule_sourceIpTextField = new JTextField(this.str_SourceIP, 20);
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.editRule_sourceIpTextField, constraints );
		jp.add( this.editRule_sourceIpTextField );
		this.editRule_destinationIpTextField = new JTextField(this.str_DestinationIP, 20);
		constraints.gridx = 1;
		constraints.gridy = 0;
		gbl.setConstraints( this.editRule_destinationIpTextField, constraints );
		jp.add( this.editRule_destinationIpTextField );
		this.editRule_sourcePortTextField = new JTextField(this.str_SourcePort, 20);
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.editRule_sourcePortTextField, constraints );
		jp.add( this.editRule_sourcePortTextField );
		this.editRule_destinationPortTextField = new JTextField(this.str_DestinationPort, 20);
		constraints.gridx = 1;
		constraints.gridy = 1;
		gbl.setConstraints( this.editRule_destinationPortTextField, constraints );
		jp.add( this.editRule_destinationPortTextField );
		this.editRule_messageTextField = new JTextField(this.str_RuleMsg, 20);
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.editRule_messageTextField, constraints );
		jp.add( this.editRule_messageTextField );
		this.editRule_classtypeTextField = new JTextField(this.str_RuleClassType, 20);
		constraints.gridx = 1;
		constraints.gridy = 2;
		gbl.setConstraints( this.editRule_classtypeTextField, constraints );
		//jp.add( this.editRule_classtypeTextField );
		this.editRule_signatureIdTextField = new JTextField(this.str_RuleSigID, 20);
		constraints.gridx = 0;
		constraints.gridy = 3;
		gbl.setConstraints( this.editRule_signatureIdTextField, constraints );
		jp.add( this.editRule_signatureIdTextField );
		this.editRule_revisionIdTextField = new JTextField(this.str_RuleRevisionID, 20);
		constraints.gridx = 1;
		constraints.gridy = 3;
		gbl.setConstraints( this.editRule_revisionIdTextField, constraints );
		jp.add( this.editRule_revisionIdTextField );
		this.editRule_timeToLiveTextField = new JTextField(this.str_TTL, 20);
		constraints.gridx = 0;
		constraints.gridy = 4;
		gbl.setConstraints( this.editRule_timeToLiveTextField, constraints );
		jp.add( this.editRule_timeToLiveTextField );
		this.editRule_sameIpTextField = new JTextField(this.str_SameIP, 20);
		constraints.gridx = 1;
		constraints.gridy = 4;
		gbl.setConstraints( this.editRule_sameIpTextField, constraints );
		jp.add( this.editRule_sameIpTextField );
		
		//-- Create radio button group for protocol --//
		this.editRule_tcpButton = new JRadioButton( "Tcp", true );
		this.editRule_tcpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 0;
		gbl.setConstraints( this.editRule_tcpButton, constraints );
		jp.add( this.editRule_tcpButton );
		this.editRule_udpButton = new JRadioButton( "Udp", false );
		this.editRule_udpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 1;
		gbl.setConstraints( this.editRule_udpButton, constraints );
		jp.add( this.editRule_udpButton );
		this.editRule_icmpButton = new JRadioButton( "Icmp", false );
		this.editRule_icmpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 2;
		gbl.setConstraints( this.editRule_icmpButton, constraints );
		jp.add( this.editRule_icmpButton );
		this.editRule_httpButton = new JRadioButton( "Http", false );
		this.editRule_httpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 3;
		gbl.setConstraints( this.editRule_httpButton, constraints );
		jp.add( this.editRule_httpButton );
		this.editRule_ftpButton = new JRadioButton( "Ftp", false );
		this.editRule_ftpButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 4;
		gbl.setConstraints( this.editRule_ftpButton, constraints );
		jp.add( this.editRule_ftpButton );
		this.editRule_tlsButton = new JRadioButton( "Tls", false );
		this.editRule_tlsButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 5;
		gbl.setConstraints( this.editRule_tlsButton, constraints );
		jp.add( this.editRule_tlsButton );
		this.editRule_smbButton = new JRadioButton( "Smb", false );
		this.editRule_smbButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 6;
		gbl.setConstraints( this.editRule_smbButton, constraints );
		jp.add( this.editRule_smbButton );
		this.editRule_dnsButton = new JRadioButton( "Dns", false );
		this.editRule_dnsButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 7;
		gbl.setConstraints( this.editRule_dnsButton, constraints );
		jp.add( this.editRule_dnsButton );
		this.editRule_ipButton = new JRadioButton( "Any protocol", false );
		this.editRule_ipButton.setHorizontalAlignment(JRadioButton.LEFT);
		constraints.gridx = 2;
		constraints.gridy = 8;
		gbl.setConstraints( this.editRule_ipButton, constraints );
		jp.add( this.editRule_ipButton );
				
		EditRuleProtocolRadioButtonHandler protocolHandler = new EditRuleProtocolRadioButtonHandler();
		this.editRule_tcpButton.addActionListener(protocolHandler);
		this.editRule_udpButton.addActionListener(protocolHandler);
		this.editRule_icmpButton.addActionListener(protocolHandler);
		this.editRule_httpButton.addActionListener(protocolHandler);
		this.editRule_ftpButton.addActionListener(protocolHandler);
		this.editRule_tlsButton.addActionListener(protocolHandler);
		this.editRule_smbButton.addActionListener(protocolHandler);
		this.editRule_dnsButton.addActionListener(protocolHandler);
		this.editRule_ipButton.addActionListener(protocolHandler);
				
		this.editRule_protocolGroup = new ButtonGroup();
		this.editRule_protocolGroup.add(this.editRule_tcpButton);
		this.editRule_protocolGroup.add(this.editRule_udpButton);
		this.editRule_protocolGroup.add(this.editRule_icmpButton);
		this.editRule_protocolGroup.add(this.editRule_httpButton);
		this.editRule_protocolGroup.add(this.editRule_ftpButton);
		this.editRule_protocolGroup.add(this.editRule_tlsButton);
		this.editRule_protocolGroup.add(this.editRule_smbButton);
		this.editRule_protocolGroup.add(this.editRule_dnsButton);
		this.editRule_protocolGroup.add(this.editRule_ipButton);
		
		//-- Create radio buttons for action --//
		this.editRule_alertButton = new JRadioButton("Alert", true);
		constraints.gridx = 3;
		constraints.gridy = 0;
		gbl.setConstraints( this.editRule_alertButton, constraints );
		jp.add(this.editRule_alertButton);	
		this.editRule_passButton = new JRadioButton("Pass" , false);
		constraints.gridx = 3;
		constraints.gridy = 1;
		gbl.setConstraints( this.editRule_passButton, constraints );
		jp.add(this.editRule_passButton);	
		this.editRule_rejectButton = new JRadioButton("Reject", false);
		constraints.gridx = 3;
		constraints.gridy = 2;
		gbl.setConstraints( this.editRule_rejectButton, constraints );
		jp.add(this.editRule_rejectButton);	
		this.editRule_dropButton = new JRadioButton("Drop", false);
		constraints.gridx = 3;
		constraints.gridy = 3;
		gbl.setConstraints( this.editRule_dropButton, constraints );
		jp.add(this.editRule_dropButton);
		
		EditRuleActionRadioButtonHandler actionHandler = new EditRuleActionRadioButtonHandler();
		this.editRule_alertButton.addActionListener(actionHandler);
		this.editRule_passButton.addActionListener(actionHandler);
		this.editRule_rejectButton.addActionListener(actionHandler);
		this.editRule_dropButton.addActionListener(actionHandler);
		
		this.editRule_actionGroup = new ButtonGroup();
		this.editRule_actionGroup.add(this.editRule_alertButton);
		this.editRule_actionGroup.add(this.editRule_passButton);
		this.editRule_actionGroup.add(this.editRule_rejectButton);
		this.editRule_actionGroup.add(this.editRule_dropButton);		

		this.editRule_contentTextBox = new JTextArea(this.str_PacketContent, 4, 20);
		constraints.gridx=0;
		constraints.gridy=5;
		gbl.setConstraints(this.editRule_contentTextBox, constraints);
		jp.add(this.editRule_contentTextBox);
		
		this.editRule_originalRuleNameTextField = new JTextField(this.str_OriginalRuleName, 20);
		constraints.gridx=1;
		constraints.gridy=5;
		gbl.setConstraints(this.editRule_originalRuleNameTextField, constraints);
		jp.add(this.editRule_originalRuleNameTextField);
		
		this.editRule_createRuleButton = new JButton("Edit rule");
		constraints.gridx = 0;
		constraints.gridy = 6;
		gbl.setConstraints( this.editRule_createRuleButton, constraints );
		jp.add(this.editRule_createRuleButton);	
		this.editRule_createRuleResetButton = new JButton("Reset rule parameters");
		constraints.gridx = 1;
		constraints.gridy = 6;
		gbl.setConstraints( this.editRule_createRuleResetButton, constraints );
		jp.add(this.editRule_createRuleResetButton);	
		
		EditRuleButtonHandler bHandler = new EditRuleButtonHandler();
		this.editRule_createRuleButton.addActionListener(bHandler);
		EditRuleResetButtonHandler resetHandler = new EditRuleResetButtonHandler();
		this.editRule_createRuleResetButton.addActionListener(resetHandler);
		
		return jp;
	}
	
	//private method to create the Log watcher control tab
	private JPanel createWatcherControlTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);
		
		this.watcherControl_StartWatchersButton = new JButton("Start Log File Watchers");
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.watcherControl_StartWatchersButton, constraints );
		jp.add(this.watcherControl_StartWatchersButton);
		
		this.watcherControl_StopWatchersButton = new JButton("Stop Log File Watchers");
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.watcherControl_StopWatchersButton, constraints );
		jp.add(this.watcherControl_StopWatchersButton);
		
		this.watcherControl_RestartWatchersButton = new JButton("Restart Log File Watchers");
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.watcherControl_RestartWatchersButton, constraints );
		jp.add(this.watcherControl_RestartWatchersButton);
		
		// watcherControl_IpAddress, watcherControl_Port
		this.watcherControl_IpAddress = new JTextField("Receiving IP Address", 20);
		constraints.gridx = 0;
		constraints.gridy = 3;
		gbl.setConstraints( this.watcherControl_IpAddress, constraints );
		jp.add(this.watcherControl_IpAddress);
		
		this.watcherControl_Port = new JTextField("Receiving Port", 20);
		constraints.gridx = 0;
		constraints.gridy = 4;
		gbl.setConstraints( this.watcherControl_Port, constraints );
		jp.add(this.watcherControl_Port);
		
		this.watcherControl_SetWatchersButton = new JButton("Set IP address and Port in Log File Watchers");
		constraints.gridx = 0;
		constraints.gridy = 5;
		gbl.setConstraints( this.watcherControl_SetWatchersButton, constraints );
		jp.add(this.watcherControl_SetWatchersButton);
		
		WatcherControlButtonHandler watcherButtonController = new WatcherControlButtonHandler();
		this.watcherControl_StartWatchersButton.addActionListener(watcherButtonController);
		this.watcherControl_StopWatchersButton.addActionListener(watcherButtonController);
		this.watcherControl_RestartWatchersButton.addActionListener(watcherButtonController);
		this.watcherControl_SetWatchersButton.addActionListener(watcherButtonController);
		
		return jp;
	}

	//private method to create the Suricata control tab
	private JPanel createSuricataControlTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);
		
		this.suricataControl_Start = new JButton("Start Suricata Engine");
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.suricataControl_Start, constraints );
		jp.add(this.suricataControl_Start);
		
		this.suricataControl_Stop = new JButton("Stop Suricata Engine");
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.suricataControl_Stop, constraints );
		jp.add(this.suricataControl_Stop);
		
		this.suricataControl_Restart = new JButton("Restart Suricata Engine");
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.suricataControl_Restart, constraints );
		jp.add(this.suricataControl_Restart);
		
		SuricataControlButtonHandler suricataControlHandler = new SuricataControlButtonHandler();
		this.suricataControl_Start.addActionListener(suricataControlHandler);
		this.suricataControl_Stop.addActionListener(suricataControlHandler);
		this.suricataControl_Restart.addActionListener(suricataControlHandler);
		
		return jp;
	}
	
	//private method to create the Suricata file control tab
	private JPanel createSuricataFileTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);
		
		this.suricataFileHandler_ChangeActionOrder = new JButton("Change Action Order on Client");
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.suricataFileHandler_ChangeActionOrder, constraints );
		jp.add(this.suricataFileHandler_ChangeActionOrder);
		
		this.suricataFileHandler_GetLogFile = new JButton("Get a Log File from Client");
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.suricataFileHandler_GetLogFile, constraints );
		jp.add(this.suricataFileHandler_GetLogFile);
		
		this.suricataFileHandler_GetRule = new JButton("Get a Rule File from Client");
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.suricataFileHandler_GetRule, constraints );
		jp.add(this.suricataFileHandler_GetRule);
		
		this.suricataFileHandler_DeleteRule = new JButton("Delete Suricata Rule");
		constraints.gridx = 0;
		constraints.gridy = 3;
		gbl.setConstraints( this.suricataFileHandler_DeleteRule, constraints );
		jp.add(this.suricataFileHandler_DeleteRule);
		
		this.suricataFileHandler_GetAllRules = new JButton("Get all Rule Files from Client");
		constraints.gridx = 0;
		constraints.gridy = 4;
		gbl.setConstraints( this.suricataFileHandler_GetAllRules, constraints );
		jp.add(this.suricataFileHandler_GetAllRules);		
		
		SuricataFileControlHandler suricataFileHandler = new SuricataFileControlHandler();
		this.suricataFileHandler_GetLogFile.addActionListener(suricataFileHandler);
		this.suricataFileHandler_GetRule.addActionListener(suricataFileHandler);
		this.suricataFileHandler_DeleteRule.addActionListener(suricataFileHandler);
		this.suricataFileHandler_ChangeActionOrder.addActionListener(suricataFileHandler);
		this.suricataFileHandler_GetAllRules.addActionListener(suricataFileHandler);
		
		this.firstActionCB = new JComboBox<String>(this.actionCB_Strings);
		constraints.gridx = 1;
		constraints.gridy = 0;
		gbl.setConstraints( this.firstActionCB, constraints );
		jp.add( this.firstActionCB );
		
		this.secondActionCB = new JComboBox<String>(this.actionCB_Strings);
		constraints.gridx = 2;
		constraints.gridy = 0;
		gbl.setConstraints( this.secondActionCB, constraints );
		jp.add( this.secondActionCB );
		
		this.thirdActionCB = new JComboBox<String>(this.actionCB_Strings);
		constraints.gridx = 3;
		constraints.gridy = 0;
		gbl.setConstraints( this.thirdActionCB, constraints );
		jp.add( this.thirdActionCB );
		
		this.fourthActionCB = new JComboBox<String>(this.actionCB_Strings);
		constraints.gridx = 4;
		constraints.gridy = 0;
		gbl.setConstraints( this.fourthActionCB, constraints );
		jp.add( this.fourthActionCB );
		
		this.suricataFileHandler_LogName = new JTextField("LogName (include '.log' extension)", 20);
		constraints.gridx = 1;
		constraints.gridy = 1;
		gbl.setConstraints( this.suricataFileHandler_LogName, constraints );
		jp.add( this.suricataFileHandler_LogName );
		
		this.suricataFileHandler_RuleName = new JTextField("RuleName (include '.rules' extension)", 20);
		constraints.gridx = 1;
		constraints.gridy = 2;
		gbl.setConstraints( this.suricataFileHandler_RuleName, constraints );
		jp.add( this.suricataFileHandler_RuleName );
		
		this.suricataFileHandler_RuleToBeDeleted = new JTextField("RuleToDelete (include '.rules' extension)", 20);
		constraints.gridx = 1;
		constraints.gridy = 3;
		gbl.setConstraints( this.suricataFileHandler_RuleToBeDeleted, constraints );
		jp.add( this.suricataFileHandler_RuleToBeDeleted );
		
		
		return jp;
	}
	
	//private method to create the Suricata Host Device manager tab
	private JPanel createDeviceManagerTab(){
		JPanel jp = new JPanel();
		jp.setSize(tabPanelWidth, tabPanelHeight);
		GridBagLayout gbl = new GridBagLayout();
		GridBagConstraints constraints = new GridBagConstraints();;
		jp.setLayout(gbl);

		this.deviceManager_HostName = new JTextField("New Device HostName", 20);
		constraints.gridx = 0;
		constraints.gridy = 0;
		gbl.setConstraints( this.deviceManager_HostName, constraints );
		jp.add( this.deviceManager_HostName );
		
		this.deviceManager_Ip = new JTextField("New Device Ip Address", 20);
		constraints.gridx = 0;
		constraints.gridy = 1;
		gbl.setConstraints( this.deviceManager_Ip, constraints );
		jp.add( this.deviceManager_Ip );
		
		this.deviceManager_Port = new JTextField("New Device Port", 20);
		constraints.gridx = 0;
		constraints.gridy = 2;
		gbl.setConstraints( this.deviceManager_Port, constraints );
		jp.add( this.deviceManager_Port );
		
		this.deviceManager_UserName = new JTextField("New Device UserName", 20);
		constraints.gridx = 0;
		constraints.gridy = 3;
		gbl.setConstraints( this.deviceManager_UserName, constraints );
		jp.add( this.deviceManager_UserName );
		//deviceManager_PasswordConfirm
		this.deviceManager_Password = new JTextField("New Device Password", 20);
		constraints.gridx = 0;
		constraints.gridy = 4;
		gbl.setConstraints( this.deviceManager_Password, constraints );
		jp.add( this.deviceManager_Password );
		
		this.deviceManager_PasswordConfirm = new JTextField("Confirm New Device Password", 20);
		//this.deviceManager_PasswordConfirm.set
		constraints.gridx = 0;
		constraints.gridy = 5;
		gbl.setConstraints( this.deviceManager_PasswordConfirm, constraints );
		jp.add( this.deviceManager_PasswordConfirm );
		
		this.deviceManager_AddDevice = new JButton("Add a New Monitored Device");
		constraints.gridx = 0;
		constraints.gridy = 6;
		gbl.setConstraints( this.deviceManager_AddDevice, constraints );
		jp.add(this.deviceManager_AddDevice);
		
		this.deviceManager_RemoveDevice = new JButton("Remove a Monitored Device");
		constraints.gridx = 1;
		constraints.gridy = 0;
		gbl.setConstraints( this.deviceManager_RemoveDevice, constraints );
		jp.add(this.deviceManager_RemoveDevice);
		
		DeviceManagerButtonHandler deviceManagerHandler = new DeviceManagerButtonHandler();
		this.deviceManager_AddDevice.addActionListener(deviceManagerHandler);
		this.deviceManager_RemoveDevice.addActionListener(deviceManagerHandler);
		
		return jp;
	}
	
	//-- end of private methods to create tabs --//
	
	//private method to get the selected devices port from the xml file
	private int getSelectedPort(){
		if(this.xmlHandler == null){
			return -1;
		}
		if(this.deviceChoice == null){
			return -1;
		}
		int port = -1;
		
		try {
			List<XML_Device> deviceList = this.xmlHandler.getAllMonitoredDevices();
			for(XML_Device xmlD : deviceList){
				if(this.deviceChoice.equals(xmlD.getHostname())){
					port = xmlD.getPortNumber();
					break;
				}
			}
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
		}
		
		return port;
	}
	
	//private method to get the selected devices IP address from the xml file
	private String getSelectedIP(){
		if(this.xmlHandler == null){
			return null;
		}
		if(this.deviceChoice == null){
			return null;
		}
		String selectedIP = "";
		
		try {
			List<XML_Device> deviceList = this.xmlHandler.getAllMonitoredDevices();
			for(XML_Device xmlD : deviceList){
				if(this.deviceChoice.equals(xmlD.getHostname())){
					selectedIP = xmlD.getIp();
					break;
				}
			}
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
		}
		
		return selectedIP;		
	}
	
	//-- private classes for event handlers --//
	
	//private class to handle selecting a protocol for creating a rule
	private class CreateRuleProtocolRadioButtonHandler implements ActionListener{
		public void actionPerformed(ActionEvent event) {
			
			if(event.getSource() == tcpButton){
				protocolChoice = "tcp";
			}
			else if(event.getSource() == udpButton){
				protocolChoice = "udp";
			}
			else if(event.getSource() == icmpButton){
				protocolChoice = "icmp";
			}
			else if(event.getSource() == httpButton){
				protocolChoice = "http";
			}
			else if(event.getSource() == ftpButton){
				protocolChoice = "ftp";
			}
			else if(event.getSource() == tlsButton){
				protocolChoice = "tls";
			}
			else if(event.getSource() == smbButton){
				protocolChoice = "smb";
			}
			else if(event.getSource() == dnsButton){
				protocolChoice = "dns";
			}
			else if(event.getSource() == ipButton){
				protocolChoice = "ip";
			}
		}		
	}
	
	//private class to handle selecting an action for creating a rule
	private class CreateRuleActionRadioButtonHandler implements ActionListener{
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == passButton){
				actionChoice = "pass";
			}
			else if(e.getSource() == alertButton){
				actionChoice = "alert";
			}
			else if(e.getSource() == dropButton){
				actionChoice = "drop";
			}
			else if(e.getSource() == rejectButton){
				actionChoice = "reject";
			}
		}
		
	}
	
	//private class to handle creating a new Rule to a device
	private class CreateRuleButtonHandler implements ActionListener{

		public void actionPerformed(ActionEvent e) {
			String chosenDevice = "";
			String ruleFileName = "";
			String ruleText = "";
			ruleText = ruleText.concat(actionChoice+" ");
			ruleText = ruleText.concat(protocolChoice+" ");
			
			if(deviceChoice == null || deviceChoice.isEmpty()){
				JOptionPane.showMessageDialog( null,"Please select a Device to receive the new rule on the left");
				return;
			}
			else{
				chosenDevice = deviceChoice;
			}
			if(ruleNameTextField.getText().isEmpty() || ruleNameTextField.getText().equals(str_Rulename)){
				JOptionPane.showMessageDialog( null,"Rule name not entered. Please enter a rule name");
				return;
			}
			else{
				ruleFileName = ruleNameTextField.getText();
			}
			if(isValidIpAddress(sourceIpTextField.getText())){
				ruleText = ruleText.concat(sourceIpTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Source IP address is not legal, please enter a legal address");
				return;
			}
			if(isValidPort(sourcePortTextField.getText())){
				ruleText = ruleText.concat(sourcePortTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Source port is not legal, please enter a legal port");
				return;
			}			
			ruleText = ruleText.concat("-> ");
			if(isValidIpAddress(destinationIpTextField.getText())){
				ruleText = ruleText.concat(destinationIpTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Destination IP address is not legal, please enter a legal address");
				return;
			}
			if(isValidPort(destinationPortTextField.getText())){
				ruleText = ruleText.concat(destinationPortTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Destination port is not legal, please enter a legal port");
				return;
			}			
			ruleText = ruleText.concat("(");
			if(!messageTextField.getText().isEmpty()){
				ruleText = ruleText.concat("msg:\""+messageTextField.getText()+"\"; ");
			}
			if(!contentTextBox.getText().isEmpty() && !contentTextBox.getText().equals(str_PacketContent)){
				ruleText = ruleText.concat("content:"+contentTextBox.getText()+"; ");
			}
			if(!signatureIdTextField.getText().isEmpty()){
				ruleText = ruleText.concat("sid:"+signatureIdTextField.getText()+"; ");
			}
			if(!revisionIdTextField.getText().isEmpty()){
				ruleText = ruleText.concat("rev:"+revisionIdTextField.getText()+"; ");
			}
			if(!timeToLiveTextField.getText().isEmpty()){
				ruleText = ruleText.concat("ttl:"+timeToLiveTextField.getText()+"; ");
			}
			if(!sameIpTextField.getText().isEmpty()){
				ruleText = ruleText.concat("sameip; ");
			}
			if(!contentTextBox.getText().isEmpty() && !contentTextBox.getText().equals(str_PacketContent)){
				ruleText = ruleText.concat("content:\""+contentTextBox.getText()+"\"; ");
			}
			//if(!classtypeTextField.getText().isEmpty()){
			ruleText = ruleText.concat("classtype:policy-violation; ");
			//}			
			ruleText = ruleText.concat(")");
			
			talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
			boolean b = talker.client_createNewRuleFile(ruleFileName, ruleText);
			JOptionPane.showMessageDialog( null,"\nChosen Device: "+chosenDevice+"\nRuleName: "+ruleFileName+"\n"+ruleText+"\n"+"Create Rule Command sent: "+b);
			writeToUpdateBox("\nChosen Device: "+chosenDevice+"\nRuleName: "+ruleFileName+"\n"+ruleText+"\n"+"Create Rule Command sent: "+b);
		}
		
	}
	
	//private class to handle the create rule reset button
	private class CreateRuleResetButtonHandler implements ActionListener{
		
		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == createRuleResetButton){
				protocolChoice = "tcp";
				tcpButton.setSelected(true);
				udpButton.setSelected(false);
				icmpButton.setSelected(false);
				httpButton.setSelected(false);
				ftpButton.setSelected(false);
				smbButton.setSelected(false);
				dnsButton.setSelected(false);
				ipButton.setSelected(false);
				
				actionChoice = "alert";
				passButton.setSelected(false);
				alertButton.setSelected(true);
				dropButton.setSelected(false);
				rejectButton.setSelected(false);
				
				sourceIpTextField.setText(str_SourceIP);
				destinationIpTextField.setText(str_DestinationIP);
				sourcePortTextField.setText(str_SourcePort);
				destinationPortTextField.setText(str_DestinationPort);
				messageTextField.setText(str_RuleMsg);
				classtypeTextField.setText(str_RuleClassType);
				signatureIdTextField.setText(str_RuleSigID);
				revisionIdTextField.setText(str_RuleRevisionID);
				timeToLiveTextField.setText(str_TTL);
				sameIpTextField.setText(str_SameIP);
				contentTextBox.setText(str_PacketContent);
				ruleNameTextField.setText(str_Rulename);				
			}
		}
	}
	
	//private class to handle the edit rule button
	private class EditRuleButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			String chosenDevice = "";
			String ruleFileName = "";
			String ruleText = "";
			ruleText = ruleText.concat(editRule_actionChoice+" ");
			ruleText = ruleText.concat(editRule_protocolChoice+" ");
			
			if(deviceChoice == null || deviceChoice.isEmpty()){
				JOptionPane.showMessageDialog( null,"Please select a Device to receive the new rule on the left");
				return;
			}
			else{
				chosenDevice = deviceChoice;
			}
			if(editRule_originalRuleNameTextField.getText().isEmpty() || editRule_originalRuleNameTextField.getText().equals(str_OriginalRuleName)){
				JOptionPane.showMessageDialog( null,"Original Rule name not entered. Please type in a rule file name");
				return;
			}
			else{
				ruleFileName = editRule_originalRuleNameTextField.getText();
			}
			if(isValidIpAddress(editRule_sourceIpTextField.getText())){
				ruleText = ruleText.concat(editRule_sourceIpTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Source IP address is not legal, please enter a legal address");
				return;
			}
			if(isValidPort(editRule_sourcePortTextField.getText())){
				ruleText = ruleText.concat(editRule_sourcePortTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Source port is not legal, please enter a legal port");
				return;
			}			
			ruleText = ruleText.concat("-> ");
			if(isValidIpAddress(editRule_destinationIpTextField.getText())){
				ruleText = ruleText.concat(editRule_destinationIpTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Destination IP address is not legal, please enter a legal address");
				return;
			}
			if(isValidPort(editRule_destinationPortTextField.getText())){
				ruleText = ruleText.concat(editRule_destinationPortTextField.getText()+" ");
			}
			else{
				JOptionPane.showMessageDialog( null,"Destination port is not legal, please enter a legal port");
				return;
			}			
			ruleText = ruleText.concat("(");
			if(!editRule_messageTextField.getText().isEmpty()){
				ruleText = ruleText.concat("msg:\""+editRule_messageTextField.getText()+"\"; ");
			}
			if(!editRule_contentTextBox.getText().isEmpty() && !editRule_contentTextBox.getText().equals(str_PacketContent)){
				ruleText = ruleText.concat("content:\""+editRule_contentTextBox.getText()+"\"; ");
			}
			if(!editRule_signatureIdTextField.getText().isEmpty()){
				ruleText = ruleText.concat("sid:"+editRule_signatureIdTextField.getText()+"; ");
			}
			if(!editRule_revisionIdTextField.getText().isEmpty()){
				ruleText = ruleText.concat("rev:"+editRule_revisionIdTextField.getText()+"; ");
			}
			if(!editRule_timeToLiveTextField.getText().isEmpty()){
				ruleText = ruleText.concat("ttl:"+editRule_timeToLiveTextField.getText()+"; ");
			}
			if(!editRule_sameIpTextField.getText().isEmpty()){
				ruleText = ruleText.concat("sameip; ");
			}
			//if(!editRule_classtypeTextField.getText().isEmpty()){
			ruleText = ruleText.concat("classtype:policy-violation; ");
			//}
			ruleText = ruleText.concat(")");
			
			talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
			boolean b = talker.client_editRuleFile(ruleFileName, ruleText);
			JOptionPane.showMessageDialog( null,"\nChosen Device: "+chosenDevice+"\nRuleName: "+ruleFileName+"\n"+ruleText+"\n"+"Edit Rule Command sent: "+b);
			writeToUpdateBox("\nChosen Device: "+chosenDevice+"\nRuleName: "+ruleFileName+"\n"+ruleText+"\n"+"Edit Rule Command sent: "+b);
		
		}
	}
	
	//private class to change the action for the edited rule
	private class EditRuleActionRadioButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == editRule_passButton){
				editRule_actionChoice = "pass";
			}
			else if(e.getSource() == editRule_alertButton){
				editRule_actionChoice = "alert";
			}
			else if(e.getSource() == editRule_dropButton){
				editRule_actionChoice = "drop";
			}
			else if(e.getSource() == editRule_rejectButton){
				editRule_actionChoice = "reject";
			}
		}		
	}
	
	//private class to change the protocol for the edited rule
	private class EditRuleProtocolRadioButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent event) {
			if(event.getSource() == editRule_tcpButton){
				editRule_protocolChoice = "tcp";
			}
			else if(event.getSource() == editRule_udpButton){
				editRule_protocolChoice = "udp";
			}
			else if(event.getSource() == editRule_icmpButton){
				editRule_protocolChoice = "icmp";
			}
			else if(event.getSource() == editRule_httpButton){
				editRule_protocolChoice = "http";
			}
			else if(event.getSource() == editRule_ftpButton){
				editRule_protocolChoice = "ftp";
			}
			else if(event.getSource() == editRule_tlsButton){
				editRule_protocolChoice = "tls";
			}
			else if(event.getSource() == editRule_smbButton){
				editRule_protocolChoice = "smb";
			}
			else if(event.getSource() == editRule_dnsButton){
				editRule_protocolChoice = "dns";
			}
			else if(event.getSource() == editRule_ipButton){
				editRule_protocolChoice = "ip";
			}
		}		
	}
	
	//private class to reset the text in the edit rule text fields
	private class EditRuleResetButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == createRuleResetButton){
				editRule_protocolChoice = "tcp";
				editRule_tcpButton.setSelected(true);
				editRule_udpButton.setSelected(false);
				editRule_icmpButton.setSelected(false);
				editRule_httpButton.setSelected(false);
				editRule_ftpButton.setSelected(false);
				editRule_smbButton.setSelected(false);
				editRule_dnsButton.setSelected(false);
				editRule_ipButton.setSelected(false);
				
				editRule_actionChoice = "alert";
				editRule_passButton.setSelected(true);
				editRule_alertButton.setSelected(false);
				editRule_dropButton.setSelected(false);
				editRule_rejectButton.setSelected(false);
				
				editRule_sourceIpTextField.setText(str_SourceIP);
				editRule_destinationIpTextField.setText(str_DestinationIP);
				editRule_sourcePortTextField.setText(str_SourcePort);
				editRule_destinationPortTextField.setText(str_DestinationPort);
				editRule_messageTextField.setText(str_RuleMsg);
				editRule_classtypeTextField.setText(str_RuleClassType);
				editRule_signatureIdTextField.setText(str_RuleSigID);
				editRule_revisionIdTextField.setText(str_RuleRevisionID);
				editRule_timeToLiveTextField.setText(str_TTL);
				editRule_sameIpTextField.setText(str_SameIP);
				editRule_contentTextBox.setText(str_PacketContent);
				editRule_originalRuleNameTextField.setText(str_OriginalRuleName);
			}
		}
	}
	
	//private class to handle the watcher control buttons
	private class WatcherControlButtonHandler implements ActionListener{
		@Override
		public void actionPerformed(ActionEvent e) {
			if(deviceChoice ==null || deviceChoice.isEmpty()){
				JOptionPane.showMessageDialog( null,"Please select a device on the left");
				return;
			}
			
			if(e.getSource() == watcherControl_StopWatchersButton){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_stopAllWatchers();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Stop All Watchers Command sent: "+b);
				writeToUpdateBox("Stop All Watchers Command sent: "+b);			
			}
			else if(e.getSource() == watcherControl_StartWatchersButton){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_startAllWatchers();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Start All Watchers Command sent: "+b);
				writeToUpdateBox("Start All Watchers Command sent: "+b);		
			}
			else if(e.getSource() == watcherControl_RestartWatchersButton){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_restartAllWatchers();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Restart All Watchers Command sent: "+b);
				writeToUpdateBox("Restart All Watchers Command sent: "+b);		
			}
			else if(e.getSource() == watcherControl_SetWatchersButton){
				String ip = watcherControl_IpAddress.getText();
				if(!isRealValidIpAddress(ip)){
					JOptionPane.showMessageDialog( null,"Ip address is not valid");
					return;
				}
				
				String port = watcherControl_Port.getText();
				if(!isRealValidPort(port)){
					JOptionPane.showMessageDialog( null,"Port is not valid");
					return;
				}
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				System.out.println("ip address: "+ip+" port: "+port);
				boolean b = talker.client_setAllWatcherSockets(ip, Integer.parseInt(port));
				JOptionPane.showMessageDialog( null,"Setting Watchers to send data to Address: "+ip +" on Port: "+port);
				writeToUpdateBox("Set Watchers address and port Command sent: "+b);		
				
			}
		}
		
	}
	
	//private class to handle the Suricata Engine control buttons
	private class SuricataControlButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			
			if(deviceChoice ==null || deviceChoice.isEmpty()){
				JOptionPane.showMessageDialog( null,"Please select a device on the left");
				return;
			}
			
			if(e.getSource() == suricataControl_Start){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_startSuricata();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Start Suricata Command sent: "+b);
				writeToUpdateBox("Start Suricata Command sent: "+b);	
			}
			else if(e.getSource() == suricataControl_Stop){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_stopSuricata();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Stop Suricata Command sent: "+b);
				writeToUpdateBox("Stop Suricata Command sent: "+b);	
			}
			else if(e.getSource() == suricataControl_Restart){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_restartSuricata();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Restart Suricata Command sent: "+b);
				writeToUpdateBox("Restart Suricata Command sent: "+b);	
			}
			
		}
		
	}
	
	//private class for adding/deleting a monitored device from the admin system
	private class DeviceManagerButtonHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == deviceManager_AddDevice){
				String ip = deviceManager_Ip.getText();
				if(!isRealValidIpAddress(ip)){
					JOptionPane.showMessageDialog( null, "Ip address is not legal.");
					return;
				}
				String port = deviceManager_Port.getText();
				if(!isRealValidPort(port)){
					JOptionPane.showMessageDialog( null, "Port is not legal.");
					return;
				}
				int port_integer = -1;
				try{
					port_integer = Integer.parseInt(port);
				}
				catch(Exception ex){
					
				}
				String hostname = deviceManager_HostName.getText();
				String username = deviceManager_UserName.getText();
				String password = deviceManager_Password.getText();
				String confirmPw = deviceManager_PasswordConfirm.getText();
				if(!password.equals(confirmPw)){
					JOptionPane.showMessageDialog( null, "Passwords do not match.");
					return;
				}
				
				XML_Device xmlDevice = new XML_Device(false, ip, hostname, port_integer, username, password);
				try {
					xmlHandler.addMonitoredDevice(xmlDevice);
					JOptionPane.showMessageDialog( null, "Device Added.");
					reinitializeDeviceRadioButtons();
					return;
				} catch (SAXException | IOException | ParserConfigurationException | TransformerException e1) {
					JOptionPane.showMessageDialog( null, "Could not add Device to list.\nException thrown: "+ e1.getMessage());
					return;
				}
			}
			else if(e.getSource() == deviceManager_RemoveDevice){
				try {
					xmlHandler.removeMonitoredDevice(deviceChoice);
					reinitializeDeviceRadioButtons();
					JOptionPane.showMessageDialog( null,"Removed Device: "+deviceChoice);
				} catch (SAXException | IOException | ParserConfigurationException | TransformerException e1) {
					JOptionPane.showMessageDialog( null,"Could not remove device");
					e1.printStackTrace();
				}
			}
		}
	}
	
	//Incomplete
	//private class to handle the button presses on the Suricata file control tab
	private class SuricataFileControlHandler implements ActionListener{

		@Override
		public void actionPerformed(ActionEvent e) {
			
			if(deviceChoice ==null || deviceChoice.isEmpty()){
				JOptionPane.showMessageDialog( null,"Please select a device on the left");
				return;
			}
			
			if(e.getSource() == suricataFileHandler_GetLogFile){				
				String logFileName = suricataFileHandler_LogName.getText();
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_getLogFile(logFileName);
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Get "+logFileName+" command sent:"+b);
				writeToUpdateBox("Get LogFile Command sent: "+b);	
			}
			else if(e.getSource() == suricataFileHandler_GetRule){
				String ruleFileName = suricataFileHandler_RuleName.getText();
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_getRuleFile(ruleFileName);
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Get "+ruleFileName+" command sent:"+b);
				writeToUpdateBox("Get RuleFile Command sent: "+b);	
			}
			else if(e.getSource() == suricataFileHandler_DeleteRule){
				String ruleFileName = suricataFileHandler_RuleToBeDeleted.getText();
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_removeRuleFile(ruleFileName);
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Remove "+ruleFileName+" command sent:"+b);
				writeToUpdateBox("Remove RuleFile Command sent: "+b);
			}
			else if(e.getSource() == suricataFileHandler_ChangeActionOrder){
				String actionOrderNumberString = "";
				
				String first = firstActionCB.getSelectedItem().toString();
				String second = secondActionCB.getSelectedItem().toString();
				String third = thirdActionCB.getSelectedItem().toString();
				String fourth = fourthActionCB.getSelectedItem().toString();
				
				actionOrderNumberString = actionOrderNumberString.concat(String.valueOf(getAction(first)));
				actionOrderNumberString = actionOrderNumberString.concat(String.valueOf(getAction(second)));
				actionOrderNumberString = actionOrderNumberString.concat(String.valueOf(getAction(third)));
				actionOrderNumberString = actionOrderNumberString.concat(String.valueOf(getAction(fourth)));
				
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_changeActionOrder(actionOrderNumberString);
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Change Actionorder to "+actionOrderNumberString+" command sent: "+b);
				writeToUpdateBox("Change Action Order Command sent: "+b);
			}
			else if(e.getSource() == suricataFileHandler_GetAllRules){
				talker.setIPAddressAndPort(getSelectedIP(), getSelectedPort());
				boolean b = talker.client_getAllRuleFiles();
				JOptionPane.showMessageDialog( null,"\nChosen Device: "+deviceChoice+"\n"+"Get All Rule Files command sent:"+b);
				writeToUpdateBox("Get All Rule Files Command sent: "+b);
			}
		}
		
	}
	
	//private class for device radio buttons to select a monitored device
	private class DeviceSelectRadioButtonHandler implements ActionListener{

		public void actionPerformed(ActionEvent e) {
			if(e.getSource() instanceof JRadioButton){
				deviceChoice = ((JRadioButton)e.getSource()).getText();
				JOptionPane.showMessageDialog( null, "Device chosen: "+deviceChoice);
				writeToUpdateBox("Device chosen: "+deviceChoice);
			}
		}
	}
	
	//-- end of private classess for event handlers --//
	
	//turn the selected rule action into an int for the client
	private int getAction(String option){
		int x = -1;
		
		if(option.equals(this.actionCB_Strings[0])){
			x=1;
		}
		else if(option.equals(this.actionCB_Strings[1])){
			x=2;
		}
		else if(option.equals(this.actionCB_Strings[2])){
			x=3;
		}
		else if(option.equals(this.actionCB_Strings[3])){
			x=4;
		}
		
		return x;
	}
	
	//check if port is real, not 'any'
	private boolean isRealValidPort(String portString){
		boolean b = false;
		try{
			int port = Integer.parseInt(portString);
			if(port>=0 && port<=65535){
				b = true;
			}			
			else{
				System.out.println("illegal port: port not in acceptable range");
			}
		}
		catch(NumberFormatException e){
			System.out.println("illegal port: not an integer");
		}
			
		return b;
	}
	
	//check if 65535 is the max for a port
	private boolean isValidPort(String portString){
		boolean b = false;
		if(portString.equals("any")){
			b = true;
		}
		try{
			int port = Integer.parseInt(portString);
			if(port>=0 && port<=65535){
				b = true;
			}			
			else{
				System.out.println("illegal port: port not in acceptable range");
			}
		}
		catch(NumberFormatException e){
			System.out.println("illegal port: not an integer");
		}
			
		return b;
	}
	
	//check if ip address is real, not 'any'
	private boolean isRealValidIpAddress(String address){
		boolean b = false;
		boolean incorrectNumber = false;
		
		//cant be null
        if(address!=null){        	
        	//cant be empty
            if(!address.isEmpty()){            	
            	//cant end in a dot
            	if(!address.endsWith(".")){            		
            		//check for 4 sections
            		String[] addressSections = address.split("\\.");
                	if(addressSections.length==4){
                		
                		//check all 4 sections of the address
                		for(int i=0; i<addressSections.length; i++){
                			try{
                				int number = Integer.parseInt(addressSections[i]);
                				if(number<0 || number>255){
                					incorrectNumber = true;
                					break;
                				}
                			}
                			catch(NumberFormatException e){
                				incorrectNumber = true;
                				e.printStackTrace();
                				break;
                			}
                		}//end for loop
                	}
                	else{
                		System.out.println("Incorrect number of sections in Ip address");
                		incorrectNumber = true;
                	}//end address sections if
            	}
            	else{
            		System.out.println("Address ends in a '.'");
                	incorrectNumber = true;            		
            	}//end ends with dot if            	
            }
            else{
            	System.out.println("Address is empty");
            	incorrectNumber = true;            	
            }//end is empty address if
        }//end null if        
        if(incorrectNumber == false){
        	b = true;
        }		
		return b;
	}
	
	//check if an ipv4 address is valid or any
	private boolean isValidIpAddress(String address){
		boolean b = false;
		boolean incorrectNumber = false;
		
		if(address.equals("any")){
			return true;
		}
		
		//cant be null
        if(address!=null){        	
        	//cant be empty
            if(!address.isEmpty()){            	
            	//cant end in a dot
            	if(!address.endsWith(".")){            		
            		//check for 4 sections
            		String[] addressSections = address.split("\\.");
                	if(addressSections.length==4){
                		
                		//check all 4 sections of the address
                		for(int i=0; i<addressSections.length; i++){
                			try{
                				int number = Integer.parseInt(addressSections[i]);
                				if(number<0 || number>255){
                					incorrectNumber = true;
                					break;
                				}
                			}
                			catch(NumberFormatException e){
                				incorrectNumber = true;
                				e.printStackTrace();
                				break;
                			}
                		}//end for loop
                	}
                	else{
                		System.out.println("Incorrect number of sections in Ip address");
                		incorrectNumber = true;
                	}//end address sections if
            	}
            	else{
            		System.out.println("Address ends in a '.'");
                	incorrectNumber = true;            		
            	}//end ends with dot if            	
            }
            else{
            	System.out.println("Address is empty");
            	incorrectNumber = true;            	
            }//end is empty address if
        }//end null if        
        if(incorrectNumber == false){
        	b = true;
        }		
		return b;
	}
} // end class Admin_GUI_Console