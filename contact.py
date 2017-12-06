# Import smtplib for the actual sending function
import smtplib
import os
import sys
# Import the email modules we'll need
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#login to gmail
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login("haccingprotecctor@gmail.com", "ishallprotecc")
# Open a plain text file for reading.  For this example, assume that
# the text file contains only ASCII characters.
textfile = os.path.join(sys.path[0], 'attackers.txt')
msg = ""

with open(textfile) as fp:
    # Create a text/plain message
    msg = MIMEText(fp.read())

#for now, sending email to myself
server.sendmail("haccingprotecctor@gmail.com", "haccingprotecctor@gmail.com", msg.as_string())
server.quit()
