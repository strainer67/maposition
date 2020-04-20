# Summary:
**MAPOSITION** is a Web application displaying the position of a mobile on a map in quasi-realtime.  
An authentification step is needed to know the position of the mobile: the user has to log on its session with its username and its password.  
![login page](/img/login.png)  
Once this step is done a marker representing the mobile is displayed on the map. A click on the marker gives information about latitude, longitude and UTC time.  
![map](/img/maposition.png)  
Some websites propose hosting like [PythonAnywhere.com](https://www.pythonanywhere.com/)
## Prerequisite
This application has a sense only if a mobile send positions. A position has to be sent via a HTTP request (query string). By default, it has to respect this nomenclure:
```
https://{my_website}/send_position?lat={lat_m}&lon={lon_m}&time={time_m}
```
where my_website is the domain name,  lat_m, lon_m the latitude and the longitude of the mobile in decimal degrees and time_m the UTC time of the position measurement. Time format has to be: %Y-%m-%dT%H:%M:%S.%fZ.
For example a valid request is:
```
https://webposition.com/send_position?lat=48.58392&lon=7.74553&time=2020-03-17T12:00:00.00Z
```
Some applications exist to send GPS position via HTTP request. As an example, the Android application [gpslogger](https://github.com/mendhak/gpslogger) developped by [mendahk](https://github.com/mendhak) can be cited.

## How does it work ?  
When a valid HTTP request is received by the web server, the request content containing the time and position of the mobile is stored in a sqlite database.  
When the user reaches the web page, first he has to fill a form (username + password) to prove its identity. Then the web server returns a map with the marker notifying the last position of the mobile. The position of the mobile is refreshing every 10 seconds (default value) by running HTTP request in background.  
A scheme worth better than long explanations.  
![flowscheme](/img/principle.png)  
## How running the application ?  
I will explain here how to run the application in local, ie on your machine.  
Clone the project:  
```
git clone git@github.com:strainer67/maposition.git
```
Go in the directory **maposition**:  
```bash
cd maposition
```
Install the dependencies (better in a virtual environment):  
```
pip3 install -r requirements.txt
```
Run the application:  
```python
python3 maposition.py
```
Open a web browser and enter the following URL:  
```
http://127.0.0.1:5000/
```
Fill the login form, by default identifiant field is **admin** and mot de passe field is **password**.  
If you want to simulate a mobile sending its position to the server, you can run the script test.py:
```python
python3 test.py
```
You could see the marker moving on the map if you wait approximately 10 seconds.
## How to manage the database ?
Positions sent by the mobile are stored in a SQLITE database, in addition of username/password of each user. To manage the database, some scipts can be used:  
First go to the directory containing the scripts for the database:
```bash
cd db
```
To Initialize a database:
```python
python3 init_db.py
```
To add a user in the database with username: **flower** and password: **lilac**:
```python
python3 add_user_db.py flower lilac
```
To remove the user **flower** in the database:
```python
python3 remove_user_db.py flower
```
## Technical details
The application was built with the python web framework Flask. For the front-end side HTML, CSS and the framework Bootstrap was used. As I already said, positions are stored in a SQLITE database. The username and the password are hashed in the database with the algorithm SHA-256, moreover each recording of latitude, longitude and time are encrypted in the database with the algorithm AES-256. The map is displayed thanks to the JavaScript library [Leaflet](https://leafletjs.com/) and position of the mobile is updated thanks to the Leaflet plugin [realtime](https://github.com/perliedman/leaflet-realtime). Map tiles are provided by [Openstreetmap](https://www.openstreetmap.org).  
The script **current_position.js** is responsible for the updates of the position. In consequence, if this application is hosted somewhere else than locally (which make sense), substitute the URL: http://127.0.0.1:5000 by the URL of your server (line 7 of current_position.js). You can also change the interval of updates, by default it is 10 s (10 000ms), line 8.
## Prospect for developers
Currently, this is the web browser (client) which ask position updates to the web server. This is done every 10s by default. It will be far more efficient that updates would be pushed by the web server to have data in realtime and to not overload the web server.One way to overcome this limitation would be to implement Web socket to have a true realtime.


