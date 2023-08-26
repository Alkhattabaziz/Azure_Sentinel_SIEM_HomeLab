<h1>Azure Sentinel (SIEM) HomeLab</h1>
<h2>Description</h2>
The purpose of this experiment is to create an environment similar to the one the enterprises face in the real world, and how the SOC team watch and analyze the data which the extract of real world cyber-attacks.
<br />
<h2>In this home lab I have used a cloud based service (Azure) and used the following tools it provides:</h2>

- <b>Virtual machines (Windows10): I made it vulnerable for outside attacks.</b> 
- <b>Log Analytics Workspace: To ingest all the logs from the VM.</b>
- <b>Azure Sentinel (SIEM): I used it to create a map of the attacks.</b>

<h2>Creating and Deploying The VM:</h2>

<p align="center">
After registering to the free Azure services, which gives a free credit of $200, and creating the VM, I have lowered the security of the VM to none by creating a new network security group in the setting of VM. 
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




</p>

