import os.path
from dotenv import load_dotenv
import traceback, logging

import smtplib,ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email import encoders
import ssl
from string import Template

# Load the .env file
load_dotenv()
passcorreo = os.getenv('PASSWORD_CORREO')


def send_email(email_recipient,
               email_subject,
               email_message,
               attachment_location = [],
               table_html='',
               imagen=''):

    email_sender = 'socarus@arus.com.co'

    msg = MIMEMultipart('mixed')
    msg['From'] = email_sender
    msg['To'] = ", ".join(email_recipient)
    msg['Subject'] = "WAZUH-SOC-"+email_subject

    html_email = Template("""
     <style>
    table {
      width: 100%;
      border-collapse: collapse;
      font-family: Arial, sans-serif;
    }
    th, td {
      border: 1px solid #dddddd;
      text-align: left;
      padding: 8px;
    }
    th {
      background-color: #001f3f;
      color: white;
    }
    tr:nth-child(even) {
      background-color: #f2f2f2;
    }

    .flyer {
      font-size: 72px;
      font-weight: bold;
      background: linear-gradient("to right", #001f3f, transparent);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .tablero {
      margin-top: 20px;
      max-width: 100%;
      border: 1px solid #ddd;
      padding: 10px;
      background: white;
    }

  </style>

   <div class="flyer">Team GTISOC</div>
  
  $email_message
    """+table_html)
    texto = html_email.substitute(email_message=email_message)

    if imagen:
        cid_name = 'tablero_cliente'
        texto = texto.replace('src="cid:tablero_cliente"', 'src="cid:tablero_cliente"')
        if '<img' not in texto and 'cid:' not in texto:
            texto += f'<div class="tablero"><img src="cid:{cid_name}" alt="Tablero de vulnerabilidades" style="width:100%; max-width:1100px;" /></div>'
        elif 'cid:' in texto:
            pass

    part1 = MIMEText(texto, 'html')
    msg.attach(part1)

    if imagen != '':
      with open(imagen, 'rb') as img:
          img_data = MIMEImage(img.read(), _subtype='png')
          img_data.add_header('Content-ID', '<tablero_cliente>')
          img_data.add_header('Content-Disposition', 'inline', filename=os.path.basename(imagen))
          msg.attach(img_data)

    if len(attachment_location) > 0:
      for file_path in attachment_location:
          if file_path == imagen:
              continue
          with open(file_path, 'rb') as f:
              file_name = os.path.basename(file_path)
              part = MIMEApplication(f.read(), Name=file_name)
              part['Content-Disposition'] = f'attachment; filename="{file_name}"'
              msg.attach(part)

    try:
        server = smtplib.SMTP('smtp.office365.com', 587)
        server.ehlo()
        server.starttls()
        server.login('socarus@arus.com.co', passcorreo)
        text= msg.as_string()
        server.sendmail(from_addr=email_sender, to_addrs=email_recipient, msg=str(text))
        print("send")
        server.quit()
    except Exception as e: # work on python 2.x
        print(traceback.format_exc())
        logging.error('La funcion "send_email", ha fallado con el error: '+ str(traceback.format_exc()))
    return True