# SHERLO-IP

![SHERLO-IP](https://i.postimg.cc/4xn5jsPk/Novo-projeto-286-B10C556.png)

---

## Description

SHERLO-IP is an asynchronous network auditing and reconnaissance tool built to analyze network traffic and extract intelligence from IP addresses. The tool processes inputs to retrieve geopolitical metadata, ISP details, Reverse DNS (PTR) records, and performs active TCP port scans alongside TLS/SSL certificate inspections.

---

## Supported IP Formats

The tool automatically validates and processes the following formats:

* Standard IPv4: 8.8.8.8
* Standard IPv6: 2001:4860:4860::8888
* IPv4 with Port: 8.8.8.8:80
* IPv6 with Port: [2001:4860:4860::8888]:443
* Quoted Strings: '8.8.8.8' or "2001:4860:4860::8888"

---

## Installation

#TERMUX
pkg update && pkg upgrade
pkg install git python
git clone [https://github.com/mrmaestrox156-debug/SHERLO-IP.git](https://github.com/mrmaestrox156-debug/SHERLO-IP.git)
cd SHERLO-IP
pip install aiohttp
python ship.py

#KALI LINUX
sudo apt update && sudo apt upgrade
sudo apt install git python3 python3-pip
git clone [https://github.com/mrmaestrox156-debug/SHERLO-IP.git](https://github.com/mrmaestrox156-debug/SHERLO-IP.git)
cd SHERLO-IP
pip3 install aiohttp
python3 ship.py
