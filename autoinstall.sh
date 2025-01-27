#!/bin/bash

# Definimos colorines
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m' # Sin color (reset)

# Actualizar
echo -e "${CYAN}--> Actualización del sistema${NC}"
sleep 2
sudo apt-get update
sudo apt-get upgrade -y

# Modificar sshd
echo -e "${CYAN}--> Configuración de sshd, cambio de puerto a 8891${NC}"
sleep 2

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.original
sed -i 's/#Port 22/Port 8891/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 30s/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#StrictModes yes/StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
sed -i 's/#MaxSessions 10/MaxSessions 3/g' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

# Reinicio sshd
sudo systemctl restart sshd

# iptables
echo -e "${CYAN}--> Configuración de iptables y sshd${NC}"
sleep 2

iptables -P FORWARD DROP

# Dependencias 3CX
echo -e "${CYAN}--> Instalación de dependencias${NC}"
sleep 2
sudo apt install -y sudo wget gnupg2 dphys-swapfile

# Clave GPG y repo 3CX
echo -e "${CYAN}--> Añadiendo la clave GPG del repositorio de 3cx${NC}"
sleep 2
wget -O- https://repo.3cx.com/key.pub | gpg --dearmor | sudo tee /usr/share/keyrings/3cx-archive-keyring.gpg > /dev/null

echo -e "${CYAN}--> Añadiendo el repositorio de 3CX...${NC}"
sleep 1
sleep 1 && echo "deb [arch=amd64 by-hash=yes signed-by=/usr/share/keyrings/3cx-archive-keyring.gpg] http://repo.3cx.com/3cx bookworm-testing main" | tee /etc/apt/sources.list.d/3cxpbx.list > /dev/null

echo -e "${CYAN}--> Actualizando los repositorios...${NC}"
sleep 2
sudo apt update

# Recordatorio ssh
echo -e "${CYAN}--> Recuerda que el próximo inicio de sesión por SSH será a través del puerto 8891${NC}"
sleep 1

# Aviso de instalación con colorines :)
echo -e "${CYAN}✓ Introduce el comando ${GREEN}sudo apt install 3cxpbx -y${NC} ${CYAN}para terminar la instalación de 3CX${NC}"
