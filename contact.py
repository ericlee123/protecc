# Import smtplib for the actual sending function
import smtplib

# Import the email modules we'll need
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

#login to gmail
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login("haccingprotecctor@gmail.com", "ishallprotecc")
# Open a plain text file for reading.  For this example, assume that
# the text file contains only ASCII characters.
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
textfile = open(os.path.join(__location__, 'attackers.txt'));

msg = ""

with open(textfile) as fp:
    # Create a text/plain message
    msg = MIMEText(fp.read())

#for now, sending email to myself
server.sendmail("haccingprotecctor@gmail.com", "haccingprotecctor@gmail.com", msg)
server.quit()