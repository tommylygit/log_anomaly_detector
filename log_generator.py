import random as rd #tirer au sort des adresses IP ou des status HTTP (générer des nombres au hasard pour simuler des fausses adresses IP et choisir des codes HTTP comme 200 ou 404)
import time #obtenir la date et l'heure exactes de mon système à la seconde près
from datetime import datetime #Créer des micro-pauses dans le script pour que les logs ne s'affichent pas tous à la même milliseconde

status_codes = ["200","404","500"]
methodes = ["GET","POST","DELETE"]
chemins_acces = ["/","/login","/api/data","/assets/style.css"]

#200 requête avec succès HTTP, #404 Page introuvable, #500 Internal Server Error
def generate_ip():
    rand1 = rd.randint(0,255)
    rand2 = rd.randint(0,255)
    rand3 = rd.randint(0,255)
    rand4 = rd.randint(0,255)
    return(f'{rand1}.{rand2}.{rand3}.{rand4}')


def generate_timestamp():
    date = datetime.now()
    return str(date.strftime("%d/%b/%Y:%H:%M:%S"))


# 27/Aug/2026:15:08:23

def generate_log_line_complet():
    return f'{generate_ip()} - - [{generate_timestamp()}] "{rd.choice(methodes)}{rd.choice(chemins_acces)} HTTP/1.1" {rd.choice(status_codes)}\n'

with open("server_log", "w") as f:
    
    for i in range(100000):

        attack = rd.random()
        if attack > 0.06:
            log = generate_log_line_complet()            
            f.write(log)
        
        elif 0 < attack <= 0.02:
            for _ in range(50):
                f.write(f'{generate_ip()} - - [{generate_timestamp()}] "{rd.choice(methodes)} {rd.choice(chemins_acces)} HTTP/1.1" 500\n')

        elif 0.02 <= attack <= 0.04:
            chemin_sensibles = ["/admin.php","/backup.zip","/.env", "/config.yaml"]
            hacker_ip = generate_ip()
            for _ in range(20):
                f.write(f'{hacker_ip} - - [{generate_timestamp()}] "GET {rd.choice(chemin_sensibles)} HTTP/1.1" 404\n')
    
        elif 0.04 <= attack <= 0.06:
            forcebrute_ip = generate_ip()
            for _ in range(50):
                f.write(f'{forcebrute_ip} - - [{generate_timestamp()}] "POST /login HTTP/1.1" 401\n')


        
