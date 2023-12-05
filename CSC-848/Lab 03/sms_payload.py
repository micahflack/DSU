import smtplib
from datetime import date

fromaddr = "mail@micahflack.com"
toaddrs  = "2182529797@vtext.com"

msg = ("From: %s\r\nTo: %s\r\n\r\n"
       % (fromaddr, ", ".join(toaddrs)))
msg = msg + f"assignment tested at {date.today()}"

# Establish a secure session with gmail's outgoing SMTP server using your gmail account
server = smtplib.SMTP( "smtp.fastmail.com", 587 )
server.starttls()
server.login( 'mail@micahflack.com', '3ucw9ej9dqdyfsuz' )

# Send text message through SMS gateway of destination number
server.sendmail( 'mail@micahflack.com', '2182529797@vtext.com', msg )
server.quit()