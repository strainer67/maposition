### Summary:
The aim of this project is to display the position of a user on an openstreetmap map. The codes in the repository consists to a web application programmated in Python with the microframework Flask.

#### Description:
In order to display the position of a user on a map, there are two main steps: 
    
    - the sending of the position of the user with a HTTP request (query string)
    - the storage of the data in a database and the display of the HTML page with a marker on a map notifying the position of the user.

The first step can be done using the project [gpslogger](https://github.com/mendhak/gpslogger) developped by [mendahk](https://github.com/mendhak). The android application can be downloaded on the Play Store. The user has to configure the URL of the HTTP request in the application. By default, to be accepted by the web application, the HTTP request has to follow this template:
    
    - http://my_website/send_position?lat={lat_user}&lon={lon_user}&time={time_user}&user_id={user_id}

The second step aims to be done by the code in the repository.  
When a valid HTTP request is received, the content is stored in a sqlite database.  
When the user reach the web page, the first step is to fill a form (username + password) to check its identity, then the user access to the map with the marker notifying its position. A  click on the marker indicates the time, the latitude and the longitude. The position of the user is refreshed thanks to the javascript code **current_position.js** every 10 seconds by default. The javascript interrogates the database via an URL (to change in current_position.js):
    
    - http://my_website/get_position

The scripts to manage (init a db, add a user, remove a user) the sqlite database are: **init_db.py**, **add_user_db.py**, **remove_user_db.py**. 
