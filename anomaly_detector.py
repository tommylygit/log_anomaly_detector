import pandas as pd #At first I wanted to use pandas with pd.read_csv, but choosing sep is quite difficult even if we choose regex

with open("server_log", "r") as file:
#IP / DATE / METHODE / CHEMIN / STATUT
#4.88.197.27 - - [07/Oct/2026:23:36:13] "DELETE/login HTTP/1.1" 500
    for line in file:
        tokens = line.split(sep='"') #tokens = [4.81.107.27 - - [07/Oct/2026:23:36:12] ,DELETE/login HTTP/1.1, 500\n]
        ip_and_date = tokens[0].split() #ip_and_date = [4.81.107.27, -, -, [07/Oct/2026:23:36:12]]
        ip = ip_and_date[0]
        date = ip_and_date[3]
        path = tokens[1]
        status = tokens[2]



            
            

        
            







