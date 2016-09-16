# Simple Blog
## Udacity Full Stack Developer Nanodegree Project 3

In order to run this blog, you need to install Google App Engine. You can see the detailed instruction of how to run Google App Engine from https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python.

If you don't have Python already you can install from here.
https://www.python.org/downloads/

After you download all of them and install them, save this repository on your local drive. Go to the folder you save this repository, type *"dev_appserver.py ."*. Then, you can go to *localhost:8080/* on your webbrowser and enjoy the blog page.

---
Information
---------
- **blog.py**: This is the python script that contains all of the class handlers for login, logout, signup, and blogs.
- **app.yaml**: This is for Google App Engine. I had to update this in order to let Google App Engine to bring *Jinja2* library and to access *css* file from **static** folder.
- **templates** folder: The folder contains all of the html templates that are used for the blog.
- **static** folder: THe folder contains the *css* file.
