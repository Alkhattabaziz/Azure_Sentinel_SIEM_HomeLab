<h1>Azure Sentinel (SIEM) HomeLab</h1>
<br />
<img src="https://i.imgur.com/zaC9xvL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />

<h2>Description</h2>
The purpose of this experiment is to create an environment similar to the one the enterprises face in the real world, and how the SOC team watch and analyze the data which the extract of real world cyber-attacks.
<br />
<h2>In this home lab I have used a cloud based service (Azure) and used the following tools it provides:</h2>

- <b>Virtual machines (Windows10): I made it vulnerable for outside attacks.</b> 
- <b>Log Analytics Workspace: To ingest all the logs from the VM.</b>
- <b>Azure Sentinel (SIEM): I used it to create a map of the attacks.</b>


<h2>Creating and Deploying The VM:</h2>

fter registering to the free Azure services, which gives a free credit of $200, and creating the VM, I have lowered the security of the VM to none by creating a new network security group in the setting of VM. 
This procedure will allow “any” traffic in the internet into my VM machine.<br/>
<br />
<img src="https://i.imgur.com/xDKKrVM.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />


<h2>Log Analytics Workspaces:</h2>

This is to ingest the Windows Event logs from the VM and create my own custom logs to be able to for a geographical information to discover where attackers are coming from.<br />
<br />
<img src="https://i.imgur.com/GGsCZPj.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />
Then I went on to Microsoft Defender to enable the ability to gather logs from the VM into the Logs Analytics Workspaces.<br />
<br />
<img src="https://i.imgur.com/qKtZ0is.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />
After that, I connected the VM to the Log Analytics Workspaces.<br />
<br />
<img src="https://i.imgur.com/qz1uoI6.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />

  
<h2>Azure Sentinel (SIEM):</h2>

Now, to be able to visualize the attacks’ data, I had to use Azure Sentinel.
So I had picked the Log Analytics Workspaces that I'd prepared earlier.<br />
<br />
<img src="https://i.imgur.com/VQ8noAc.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />

  
<h2>Working inside the VM:</h2>
<img src="https://i.imgur.com/zTikjB2.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />
While waiting for other services to connected inside Azure, I turned the firewall of the VM off so that it can be susceptible to ICMP requests from the world to be discovered faster.
I turned the Firewall state of the Domain Profile as well as Private Profile, Public Profile (See picture below):<br />
<br />
<img src="https://i.imgur.com/MHWWw6A.png height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />
  
Then I had downloaded a powershell script from an open source to which will log all the failed attempts of logins from Windows Event Viewer extract the geolocation data:
https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1 

I needed to sign up to get the API key from https://ipgeolocation.io/ to be able to convert the IP addresses into longitude and latitude.

After that, I used the Powershell ISE to run the script I had downloaded earlier then saved it on the desktop. I called it “Log_Exporter”.<br />
<br />
<img src="https://i.imgur.com/h1okYGc.png" height="80%" width="80%" alt="Disk Sanitization Steps"/><br />
<br><br/>
All the logs from the run script will be sent to https://ipgeolocation.io/ with the use of the generated API then saved automatically to a file called “failed_rdp”, and to access it I had to type “Run” in Windows search bar and type in this path (Because it’s a hidden file): C:\ProgramData\ <br /><br />
<img src="https://i.imgur.com/2NmINYX.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />



<h2>Linking VM logs to LAW:</h2>
I went to Log Analytics Workspaces, then Custom logs tab to add the file I had created earlier “FailedRDP”.
*Note: Since the actual file is on the VM, I had to create a new file on my personal computer using Notepad, and copy-paste the data from the VM to the new one on my personal desktop. Now I should be able to upload the sample log.<br />
<br />
<img src="https://i.imgur.com/McHoTUS.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
To test the logs, I went to the Logs tab under the General section in the LAW, AND RUN THE QUERY: FAILED_RDP_WITH_GEO_CL
It was named this way when I created the custom log in the previous step.
<br />
<br />
<h2>Setup Map in Sentinel:</h2>
<img src="https://i.imgur.com/BKctvmq.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br /><br />
Since everything is ready, now I had to extract the raw data and show it in a presentable way.
In Azure Sentinel, I went to the Workbook tab then ran this query (obtained from an open source) which separates the columns of the raw data and arranges them so it’s more relevant and easy to read.

<br /><br />

Query:<br />

FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData), 
timestamp = extract(@"timestamp:([^,]+)", 1, RawData), 
latitude = extract(@"latitude:([^,]+)", 1, RawData), 
longitude = extract(@"longitude:([^,]+)", 1, RawData), 
sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData), 
state = extract(@"state:([^,]+)", 1, RawData), 
label = extract(@"label:([^,]+)", 1, RawData), 
destination = extract(@"destinationhost:([^,]+)", 1, RawData), 
country = extract(@"country:([^,]+)", 1, RawData) 
| where destination != "samplehost" 
| where sourcehost != "" 
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
<br /><br />
<img src="https://i.imgur.com/Fuk15Vw.png" height="80%" width="80%" alt="Disk Sanitization Steps"/><br/>
<br /><br />
Then I changed the visualization to Map. 
I was playing a bit with the Map settings to refine the presentation of the map.<br/>
<br />
<img src="https://i.imgur.com/5JXKVlG.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br><br/>
<h2>Final Result:</h2>
<img src="https://i.imgur.com/Yccx7Nl.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


