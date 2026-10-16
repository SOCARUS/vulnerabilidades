#!/bin/bash

# Ir a la carpeta del proyecto (opcional pero recomendado)
cd /opt/vulnerabilidades/


# Activar entorno virtual 
source ./venv/bin/activate

# Ejecutar tu script Python
python clientes.py


#0 5 * * * sh /opt/vulnerabilidades/ejecutables/diarias.sh >> /opt/vulnerabilidades/logs/crontab.log 2>&1