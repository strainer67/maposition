# How to deploy a website on a server at home ?

First of all, I am not an expert of the deployment. I deployed the web application *maposition* on my raspberry pi 3 at home. It's quite amazing all the
information that i could find on internet about Web deployment. I will give in this tutorial the main steps to succeed.
* First, make static the IP adress of your server in your local network. To do that, connect to your Internet box via a web browser and change the settings. In my case (internet box from Orange), I tape 192.168.1.1 in the URL bar of an Internet browser, then click on the tab "Réseau", go to tab "DHCP", then go to "Baux DHCP statiques" and add your equipment. 
* Set up a reverse proxy on your server, for example [NGINX](https://www.nginx.com/) and make a simple configuration file. I mean redirect all the request arriving on port 80 toward your web application (http://localhost:5000) in my case. 
* Now you could reach your web application in your local network. If you set to 192.168.1.10, the IP adress of your server, then in a web browser enter in the URL bar 192.168.1.10 and you could see the login page of the application.
* You can make more complex the configuration file of NGINX, adding some features. For example, you can limit the number of request per minut allowed by a IP...
* In order to reach from the outside the web application, the port 80 (HTTP) and the port 443 (HTTPS) have to be opened on your Internet box. So from the web page of the settings of your internet box (192.168.1.1 in my case), click on the tab "Réseau", go to the tab "NAT/PAT" and add the rules for your server, ie open the port 80 of the internet box and redirect the requests on it toward the same port of your equipment. Do the same for port 443.
* Buy a domain name for example at [OVH](https://www.ovh.com/fr/domaines/) and modify the DNS of OVH to link your public IP adress to the domain name or subdomain name you chose. However if your public IP adress is not static, this method has its limit since when your ISP will change your public IP address, you could not reach anymore your application.
* In the case your public IP address is not static, you should consider a dynamic DNS. OVH proposes this service. You will have to install a software on your server, for example [ddclient](https://doc.ubuntu-fr.org/ddclient) which will run in the background and will notify to the dynamic DNS your change of public IP address.
* Once this step is done, update the configuration file of NGINX by replacing your local IP address (for example 192.168.1.10) by your domain name or subdomain name.
* Now the application can be reached directly from a web browser writing the domain name or the subdomain name in the URL bar of the web browser.
* For security reasons and privacy reasons you should consider that the access to your application has to be done via HTTPS and not HTTP. In order to allow HTTPS you need a certificate delivered by a certification authority. One of them is [Let's Encrypt](https://letsencrypt.org/). If you use NGINX a certificate and a key can be obtained writing few command lines in the terminal of your Web server (https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-18-04). Moreover it will automatically modify your NGINX configuration file to allow connection on port 443 and if i remember well it redirects all the connexion from port 80 to port 443. At first glance, encryption can appeared complicated but the software letsencrypt render it easier. The certificate obtained is valid 90 days and a command exist to renew automatically the certificate.  

NB: For deployment it is adviced to use a production WGSI server, ie not Werkzeug, the native WGSI of Flask. Personnaly I used [Gunicorn](https://gunicorn.org/).   

In order to complete the main ideas let's do a scheme:  
![deployment](/deployment.png)

