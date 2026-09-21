import random as rd
from datatime import datatime
import time

chemins_acces = ["/data", "/home"]
code_erreur = ["200, 404", "500"]

def generate_ip():
    nombre1 = rd.randint(0,256)
    nombre2 = rd.randint(0,256)
    nombre3 = rd.randint(0,256)
    nombre4 = rd.randint(0, 256)
    return f'{nombre1}.{nombre2}.,{nombre3}.{nombre4}'

def generate_timestamp():
    date = datetime.now()
    return str(date.strftime("%d/%b/%Y:%H:%M:%S"))