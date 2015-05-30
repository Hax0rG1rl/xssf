# Overview #
The Cross-Site Scripting Framework (**XSSF**) is a security tool designed to turn the XSS vulnerability exploitation task into a much easier work. The XSSF project aims to demonstrate the real dangers of XSS vulnerabilities, vulgarizing their exploitation. This project is created solely for education, penetration testing and lawful research purposes.

XSSF allows creating a **communication channel** with the targeted browser (from a XSS vulnerability) in order to perform further attacks. Users are free to select existing modules (a module = an attack) in order to target specific browsers.

XSSF provides a powerfull documented API, which facilitates development of modules and attacks. In addition, its integration into the **Metasploit Framework** allows users to launch MSF browser based exploit easilly from an XSS vulnerability.


In addition, an interesting though exploiting an XSS inside a victim's browser could be to browse website on attacker's browser, using the connected victim's session. In most of cases, simply stealing the victim cookie will be sufficient to realize this action. But in minority of cases (intranets, network tools portals, etc.), cookie won't be useful for an external attacker. That's why **XSSF Tunnel** was created to help the attacker to help the attacker browsing on affected domain using the victim's session.


<font color='blue'>
<b>This work is the result of an internship studies conducted for the <a href='http://www.cryptis.fr/'>Faculty of Science and Technology of Limoges (MASTER II Cryptis)</a> within <a href='http://blog.conixsecurity.fr/'>CONIX Security</a> company.</b>
</font>


<font color='green'><h1>Status: Working !</h1>
<h4>XSSF project is working again (beter late than never :P)! Sorry for the delay.<br>
<br>
New version is supported by current MSF 4.6.0-dev and Backtrack 5R3 / Ubuntu 12.04 / Kali 1.0 / Windows 7 (at least).<br>
<br>
Please report bugs if encountered.</h4></font>

# Download & Install #
Download can be done directly with the last packaged version in download section. Using the **SVN repository** is a better way of downloading and updating XSSF as the SVN trunk version is always up-to-date.

Installation is made to be easy and downloaded files only have to be placed within Metasploit installation directory. For people having installation issues, please refer you to the project [Wiki pages](http://code.google.com/p/xssf/wiki/Install). Installation on Ubuntu systems is explained [here](http://securitystreetknowledge.com/?p=445) in case Wiki pages are not sufficient.

| **XSSF Basics: Install (Kali-1.0) & Use** |
|:------------------------------------------|
|<a href='http://www.youtube.com/watch?feature=player_embedded&v=AhUhOirEfTE' target='_blank'><img src='http://img.youtube.com/vi/AhUhOirEfTE/0.jpg' width='425' height=344 /></a>|

For German users, XSSF and MSF explanation is available within the [Michael Messner's book](http://www.dpunkt.de/buecher/3588.html).

# Report bug #
Please report bugs directly inside "**Issues**" section! You can also email me at ludovic.courgnaud /at\ gmail.com. To report a bug, please load XSSF using '`load xssf Mode=Debug`' command and join the error to your ticket or email.

Before reporting bug, make sure your MSF version is up-to-date (XSSF is not supported anymore or MSF < 3.4). It is also better using Ruby version >= 1.9.1 up-to-date.


# Contribute #
Feel free to send your comments or give your opinion to improve the XSS Framework at ludovic.courgnaud /at\ gmail.com.

XSSF new modules can be sent to the same address. Don't forget to fill your name in the module initialization author field and / or the original discoverer name.

Follow me on twitter (http://twitter.com/#!/X0x1RG9f) to be alerted of new updates!


# Videos #
**Note:** For better quality and annotations inclusion, videos should be watched directly on Youtube.
| **Simple XSSF attack (Stealing file on Xperia X10)** | **Launching MSF exploit through XSSF (CVE-2010-2568)** | **XSSF Tunnel (Surfing through targeted browser)** |
|:-----------------------------------------------------|:-------------------------------------------------------|:---------------------------------------------------|
|<a href='http://www.youtube.com/watch?feature=player_embedded&v=hvHc0RTCAqE' target='_blank'><img src='http://img.youtube.com/vi/hvHc0RTCAqE/0.jpg' width='425' height=344 /></a>|<a href='http://www.youtube.com/watch?feature=player_embedded&v=UpXfD5LMkZo' target='_blank'><img src='http://img.youtube.com/vi/UpXfD5LMkZo/0.jpg' width='425' height=344 /></a>|<a href='http://www.youtube.com/watch?feature=player_embedded&v=1sz3g7bSKXU' target='_blank'><img src='http://img.youtube.com/vi/1sz3g7bSKXU/0.jpg' width='425' height=344 /></a>|