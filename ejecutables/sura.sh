#!/bin/bash

# Ir a la carpeta del proyecto (opcional pero recomendado)
cd /opt/vulnerabilidades/


# Activar entorno virtual
source ./venv/bin/activate

# Ejecutar tu script Python
python sura.py


#0 5 * * 5 sh /opt/vulnerabilidades/ejecutables/sura.sh >> /opt/vulnerabilidades/logs/crontab.log 2>&1