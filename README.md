# pyonline
A simple, threaded Python webserver, with very basic security features. **NOT** reccomended for professional use, but is free to being expanded.

## Installing
PyOnline requires Python 3.12 to be installed on your machine. Some third-party libraries are also required, but they can be easily installed by running the script `pipinstall.bat` for Windows machines or `pipinstall.sh` for Linux-based machines.
The default location for your website is in the `site` subfolder, and the home page is set to be `index.html`, but both of these can be changed in the configurations.
To start PyOnline, run the script `run.bat` if you're on Windows or the script `run.sh` if you are using a Linux based system.

## Configurations
Configurations for PyOnline are located at the top of the `webserver.py` script, as constants. Here are their explanations, in order of comparison:
- `SITENAME`: The name of your website. This will be shown in logs and in error pages.
- `SITEFOLDER`: The subfolder in which your website is located. The default is `site`.
- `RUNSUBFOLDER`: This is a subfolder of the site folder, in which your back-end scripts should be located for execution.
- `INDEXPAGE`: The location of your home page. The default is `site/index.html`.
- `ERROPAGE`: The default page (in HTML code) shown to the user upon an error response. Any variable from inside the script can be shown in it. For example, by default the variables `SITENAME` and `errorCode` are used, but the page is still very basic.
- `USEDNS`: Boolean, whether or not to update the IP for the default DNS service. The default is `True`.
- `FREEDNSTOKEN`: The token for the DNS service. Currently, in PyOnline, only the service FreeDNS can be used, but this can be easily changed through the code (the API URL is not modifyable from the costants, yet).
- `SERVERADDRESS`: The address on your machine for the server hosting. The default is `('', 80)`, where the first variable is the host and the second is the port. It is advised to leave the host blank and port 80 as the default port, because that is the default port for web pages.
- `BANNEDIPSFILE`: PyOnline has an automatic malicious IP detection feature, connected to the SpamHaus API. Any malicious IP within the SpamHaus database will be denied access from your website and added to the list in this file when requesting your website. The default is `data/bannedips.lst`.
- `LOGGINGENABLED`: Boolean, whether or not to log all the console output into a log file. The default is `True`.
- `LOGSFOLDER`: The folder in which all logs file will be written. The default is `logs`.
- `SUSPICIOUSKEYWORDS`: All requests which contain one of these keywords, commonly used in attacks, will be denied access to your website.

## Back-end
All of your back-end script must be contained within the `RUNSUBFOLDER`. The only accepted scipt type, for now, are Python script.
For example, the script `helloworld.py` can be executed by requesting its path. For example, it would be executed by the request `http://www.yourwebsite.com/run/helloworld.py`, if the run folder is set to its default. The response given is what the script would have outputed to the console. In our example, if the Python script is `print("Hello World!")`, then the response given to the client is the string `Hello World!`.

## For Linux users
PyOnline was made in Windows and tested to work only on Windows.
However, I have made corresponding scripts to use for Linux users as well, such as `run.sh` and `pipinstall.sh`.
I don't have a Linux machine or Virtual Machine to test them, so I think they need to have executable permissions, which is your responsability to apply.
The program SHOULD also work on Linux machines, hopefully, but I'm not certain.

## Notes
I, _Vprtp_ on GitHub, also known as _prtp_ elsewhere, am not an experienced programmer and I'm learing everything by myself with the help of the Internet. English isn't my first language either, and this is the first project I publish here on GitHub.
So, please, be understanding if there is any error you found in this file or in the project.
Have a nice day.
