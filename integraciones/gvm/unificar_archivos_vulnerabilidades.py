from dotenv import load_dotenv
import os
import paramiko

# Load the .env file
load_dotenv()


host = "10.54.49.14"
user = "arusadm"
password = os.getenv('PASSWORD_DEVSERVER')
local_file = "backlog_vulnerabilidades.csv"
remote_file = "/opt/vulnerabilidades/integraciones/gvm/gvm.csv"

transport = paramiko.Transport((host, 22))
transport.connect(username=user, password=password)

sftp = paramiko.SFTPClient.from_transport(transport)
sftp.put(local_file, remote_file)

sftp.close()
transport.close()