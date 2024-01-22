#/usr/bin/python3

import re
import subprocess
import time
from collections import defaultdict

#Agnado-Project Forefront ciberseguranca
#Project - script integration in wazuh
#bloqueio de IPs com 5 tentativas de login ssh failed

def get_ips_from_logs(log_file):
    # Lê o arquivo de log e extrai os IPs associados à mensagem específica
    with open(log_file, 'r') as f:
        log_content = f.read()
        ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+).*Attempt to login using a non-existent user', log_content)
        return ip_matches

def block_ip(ip_address):
    # Bloqueia o IP usando iptables
    block_ip_command = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
    #Aqui usa o subprocess para executar comandos do sistema
    subprocess.run(block_ip_command, shell=True)

def main(log_file):
    ip_counter = defaultdict(int)

    while True:
        ips = get_ips_from_logs(log_file)

        for ip in ips:
            ip_counter[ip] += 1
                #se o ip tiver 5 tentativas is bloqueado
            if ip_counter[ip] >= 5:
                print(f'Bloqueando IP {ip} por ataque repetido.')
                block_ip(ip)
                ip_counter[ip] = 0  # Reinicia a contagem após bloquear

        time.sleep(5)  # Aguarda 5 segundos antes de verificar novamente

if __name__ == "__main__":
    log_file_path = "/var/ossec/logs/alerts/alerts.json"  # caminho correto de log
    main(log_file_path)
