import requests
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import dns.resolver
import dns.exception
from subprocess import run
import sys
from email.utils import formatdate, parsedate_to_datetime
import socket

SITENAME = "Insert here the name of your website."
SITEFOLDER = "site"
RUNSUBFOLDER = "/run"
INDEXPAGE = "site/index.html"
ERRORPAGE = "<!DOCTYPE html><html xmlns='http://www.w3.org/1999/xhtml'><head><title>{SITENAME} - Error</title></head><body><h1>Error code: {errorCode}</h1><p>Sorry! The server has encountered an error processing your request.</p><a href='javascript:history.back()'>Go back</a></body></html>"
USEDNS = True
FREEDNSTOKEN = "Insert here your FreeDNS token, if you have one."
SERVERADDRESS = ('', 80)
BANNEDIPSFILE = "data/bannedips.lst"
LOGGINGENABLED = True
LOGSFOLDER = "logs"
SUSPICIOUSKEYWORDS = [
    # System Commands
    "cmd", "exec", "shell", "bash", "wget", "curl", "scp", "ftp", 
    "powershell", "chmod", "chown", "sudo", "kill", 
    "killall", "iptables",
    # File Access and Manipulation
    "write", "delete", "remove",
    "dir", "tmp", "backup", "dump", "../../", "%2e%2e%2f",
    # Sensitive or Default File and Directory Names
    "passwd", "shadow", "htaccess", "htpasswd", "db", "admin", "login", 
    "root", "conf", "config", "setup", "install", "private", "secret", 
    "key", "cert", "env", "log", "session", "credentials",
    # Common Exploitation Techniques
    "select", "union", "insert", "delete", "drop", "truncate", 
    "declare", "alert", "onerror", "eval", "document.cookie", 
    "cross-site", "xss", "csrf", "injection", "overflow", "buffer", 
    "cmd.exe",
    # Commonly Exploited Paths and Endpoints
    "/cgi-bin/", "/bin/", "/etc/", "/var/", "/tmp/", "/home/", "/proc/", 
    "/boot/", "/mnt/", "/dev/", "/sys/", "/lib/", "/usr/", "/sbin/", 
    "/windows/", "/winnt/", "/system32/", "/wp-admin/", "/wp-login/", 
    "/phpmyadmin/", "/mysql/", "/webdav/",
    # SQL Injection Indicators
    "' OR '1'='1", "' OR '1'='1' --", "--", ";", "#", "/*", "' OR 1=1 --", 
    "' AND 1=1 --", "xp_cmdshell", "sp_executesql", "information_schema", 
    "UNION SELECT",
    # Authentication and Authorization Bypass
    "bypass", "auth", "token", "session", "jwt", "oauth", "ldap", 
    "login", "signup", "reset", "forgot", "2fa", "mfa",
    # Malware Distribution Indicators
    "payload", "exploit", "shellcode", "rce", "reverse", "meterpreter", 
    "exploit-db", "backdoor", "trojan", "virus", "worm", "botnet", "malware"
]

threads = []

def getTimezoneOffset():
    local_time = datetime.now(timezone.utc).astimezone() # Get the current time in the local timezone
    offset = local_time.utcoffset().total_seconds() # Get the UTC offset in seconds
    return f"UTC{'+' if offset >= 0 else '-'}{int(abs(offset) // 3600):02}" # Return the timezone offset in UTC+X or UTC-X format

def beginDateTimeLog():
    old_out = sys.stdout

    class StAmpedOut:
        """Stamped stdout."""
        
        nl = True

        def write(self, x):
            """Write function overloaded."""
            now = datetime.now()
            year = now.year
            month = now.month
            day = now.day
            hour = now.hour
            minute = now.minute
            second = now.second
            timeZone = getTimezoneOffset()
            if x == '\n':
                message = x
                self.nl = True
            elif self.nl:
                message = f"[{day:02}-{month:02}-{year} {hour:02}:{minute:02}:{second:02} {timeZone}]: {x}"
                self.nl = False
            else:
                message = x

            old_out.write(message)
            if LOGGINGENABLED == True:
                with open(f"{LOGSFOLDER}/log_{day:02}-{month:02}-{year}.txt",'a') as f:
                    f.write(message)

        def flush(self):
            """Flush function overloaded."""
            old_out.flush()

    sys.stdout = StAmpedOut()

def syncFreeDNS(token):
    req = requests.get(f"http://sync.afraid.org/u/{token}/")
    retVar = req.content.decode('UTF-8').split('\n')[0]
    return retVar

def check_ip_spamhaus(ip):
    try:
        # Reverse the IP address
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query = f'{reversed_ip}.sbl.spamhaus.org'
        
        # Perform the DNS query
        try:
            dns.resolver.resolve(query, 'A')
            return True #, "Listed in Spamhaus SBL"
        except dns.resolver.NXDOMAIN:
            return False #, "Not listed in Spamhaus SBL"
        except dns.resolver.NoAnswer:
            return False #, "No answer from Spamhaus SBL"
        except dns.resolver.Timeout:
            return None #, "Timeout while querying Spamhaus SBL"
    except Exception as e:
        print(f"Error checking IP {ip}: {e}")
        return None#, "Error"
    
def isRequestSuspicious(request:str):
    for keyword in SUSPICIOUSKEYWORDS:
        if keyword in request.lower():
            return True
    return False

def isIPBanned(ip):
    with open(BANNEDIPSFILE, 'r') as f:
        bannedIPsList = f.read().split('\n')
    if ip in bannedIPsList:
        return True
    else:
        return False

def sendError(self, error):
    self.send_response(error)
    self.wfile.write(bytes(ERRORPAGE.format(SITENAME=SITENAME,errorCode=error), encoding='UTF-8'))

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args):
        pass
    
    def do_GET(self):
        clientAddr = str(self.client_address[0])
        request = self.path
        os.environ['REMOTE_ADDR'] = clientAddr

        # Check if IP is banned or request is suspicious
        if isIPBanned(clientAddr) or isRequestSuspicious(request):
            sendError(self, 403)
            print(request)
            print(f"IP {clientAddr} tried to request but it was already banned or his request was suspicious. Request: {request}")
            return

        # Check if IP is listed on Spamhaus and ban it if so
        if check_ip_spamhaus(clientAddr):
            sendError(self, 403)          
            with open(BANNEDIPSFILE, 'a') as f:
                f.write(clientAddr + '\n')
            print(f"IP {clientAddr} tried to request but it was found malicious and banned.")
            return

        # Handle request for index page
        if request == '/':
            filepath = INDEXPAGE
            self.handle_file_request(filepath, clientAddr, request)
            return
        
        # Handle request for Python script execution
        elif request.startswith(RUNSUBFOLDER):
            filepath = SITEFOLDER + request
            if os.path.isfile(filepath) and filepath.endswith('.py'):
                self.send_response(200)
                result = run(
                    ['python', filepath],
                    capture_output=True,  # Capture stdout and stderr
                    text=True,            # Return output as a string
                    check=True            # Raise an exception on a non-zero exit code
                )
                self.end_headers()
                self.wfile.write(bytes(str(result.stdout), encoding='UTF-8'))
                print(f"IP {clientAddr} requested the execution of {request} successfully.")
            else:
                sendError(self, 404)
                print(f"IP {clientAddr} requested a missing or unexistent script: {request}")
            return
        
        # Handle request for a regular file
        else:
            try:
                fileExtension = request.split('.')[1]
                filepath = SITEFOLDER + request
            except:
                filepath = SITEFOLDER + request + ".html"
            self.handle_file_request(filepath, clientAddr, request)

    def handle_file_request(self, filepath, clientAddr, request): #Not sure if this actually works.
        if os.path.isfile(filepath):
            if 'If-Modified-Since' in self.headers:
                file_modified_time = datetime.fromtimestamp(
                    os.path.getmtime(filepath), 
                    tz=timezone.utc
                )
                request_time = parsedate_to_datetime(self.headers['If-Modified-Since'])

                if file_modified_time <= request_time:
                    self.send_response(304)
                    self.end_headers()
                    print(f"IP {clientAddr} requested {request}, not modified since last fetch.")
                    return

            self.send_response(200)
            self.send_header("Last-Modified", formatdate(os.path.getmtime(filepath), usegmt=True))
            self.end_headers()

            with open(filepath, 'rb') as file:
                self.wfile.write(file.read())
            print(f"IP {clientAddr} requested {request} successfully.")
        else:
            sendError(self, 404)
            print(f"IP {clientAddr} requested a missing or unexistent file: {request}")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def main():
    beginDateTimeLog()
    print("-~"*44)
    print(f"{SITENAME.upper()} - PyOnline")
    print(f"Set webserver host: {SERVERADDRESS[0]:20}\t| Set webserver port: {SERVERADDRESS[1]}")
    print(f"Current local IP: {get_local_ip():20}\t| Current public IP: {requests.get('https://api.ipify.org').content.decode('utf8')}")
    if USEDNS == True:
        print("Updating IP for FreeDNS...")
        print(syncFreeDNS(FREEDNSTOKEN))
    print("Server started.")
    print("-~"*44)
    server = ThreadingHTTPServer(SERVERADDRESS, RequestHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()