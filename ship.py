import asyncio
import aiohttp
import os
import socket
import ssl
import sys
import ipaddress

# Configuração de Cores Estrita (100% Verde Terminal)
GREEN = "\033[0;32m"
BOLD_GREEN = "\033[1;32m"
RESET = "\033[0m"

TXT = {
    "PT": {
        "loading": "Carregando modulos de varredura...",
        "input_ip": "Digite o IP (v4/v6) do Wireshark: ",
        "invalid_ip": "Erro: Formato de IP invalido ou ilegivel.",
        "scanning": "Disparando queries assincronas e analisando tráfego real...",
        "sec_geo": "--- METADADOS GEOPOLITICOS E PROVEDOR ---",
        "sec_ident": "--- LOGISTICA DE IDENTIDADE E SEGURANCA ---",
        "sec_ssl": "--- INSPECAO DE CERTIFICADO DIGITAL TLS/SSL ---",
        "sec_ports": "--- SUPERFICIE DE ATAQUE (PORT SCAN ATIVO) ---",
        "lbl_ip": "Endereço IP:",
        "lbl_type": "Tipo de Rede:",
        "lbl_asn": "ASN / Bloco de Rede:",
        "lbl_isp": "Provedor (ISP):",
        "lbl_loc": "Cidade / Pais:",
        "lbl_zip": "Codigo Postal:",
        "lbl_tz": "Fuso Horario:",
        "lbl_maps": "Coordenadas Satelite (Maps):",
        "lbl_rdns": "Reverse DNS (PTR):",
        "lbl_tor": "Rede Anonima Tor (Exit Node):",
        "lbl_vpn": "Classificacao da Conexao:",
        "tor_yes": "ALERTA: Conexao vinda de No de Saida Tor",
        "tor_no": "Limpo (Conexao Direta)",
        "vpn_yes": "SUSPEITO (Infraestrutura Corporativa / Hosting / VPN)",
        "vpn_no": "Seguro (IP Residencial / Movel)",
        "ssl_cn": "Validado para (Common Name):",
        "ssl_org": "Organizacao / Empresa:",
        "ssl_issuer": "Autoridade Certificadora:",
        "ssl_subs": "Sites Co-Hospedados / Subdominios Vinculados:",
        "port_open": "Porta Aberta",
        "no_ports": "Nenhuma das portas especificadas respondeu como aberta.",
        "invalid_opt": "Opçao Invalida."
    },
    "EN": {
        "loading": "Loading scanning modules...",
        "input_ip": "Enter the IP (v4/v6) from Wireshark: ",
        "invalid_ip": "Error: Invalid or unreadable IP format.",
        "scanning": "Firing asynchronous queries and analyzing real traffic...",
        "sec_geo": "--- GEOPOLITICAL AND PROVIDER METADATA ---",
        "sec_ident": "--- IDENTITY AND SECURITY LOGISTICS ---",
        "sec_ssl": "--- TLS/SSL DIGITAL CERTIFICATE INSPECTION ---",
        "sec_ports": "--- ATTACK SURFACE (ACTIVE PORT SCAN) ---",
        "lbl_ip": "IP Address:",
        "lbl_type": "Network Type:",
        "lbl_asn": "ASN / Network Block:",
        "lbl_isp": "Provider (ISP):",
        "lbl_loc": "City / Country:",
        "lbl_zip": "Postal Code:",
        "lbl_tz": "Time Zone:",
        "lbl_maps": "Satellite Coordinates (Maps):",
        "lbl_rdns": "Reverse DNS (PTR):",
        "lbl_tor": "Tor Anonymous Network (Exit Node):",
        "lbl_vpn": "Connection Classification:",
        "tor_yes": "ALERT: Connection from Tor Exit Node",
        "tor_no": "Clean (Direct Connection)",
        "vpn_yes": "SUSPICIOUS (Corporate Infrastructure / Hosting / VPN)",
        "vpn_no": "Secure (Residential / Mobile IP)",
        "ssl_cn": "Validated for (Common Name):",
        "ssl_org": "Organization / Company:",
        "ssl_issuer": "Certifying Authority:",
        "ssl_subs": "Co-Hosted Sites / Linked Subdomains:",
        "port_open": "Port Open",
        "no_ports": "None of the specified ports responded as open.",
        "invalid_opt": "Invalid Option."
    }
}

async def exibir_carregamento():
    sys.stdout.write(GREEN)
    for i in range(1, 101):
        barra = "█" * (i // 4)
        espaco = " " * (25 - (i // 4))
        sys.stdout.write(f"\r[{barra}{espaco}] {i}%")
        sys.stdout.flush()
        await asyncio.sleep(0.006)
    sys.stdout.write("\n")

async def digitar_opcao(texto, atraso=0.015):
    for i in range(len(texto) + 1):
        sys.stdout.write(f"\r{GREEN}{texto[:i]}█")
        sys.stdout.flush()
        await asyncio.sleep(atraso)
    sys.stdout.write(f"\r{GREEN}{texto} \n")
    sys.stdout.flush()

def limpar_e_validar_ip(entrada_bruta):
    entrada = entrada_bruta.strip().replace("'", "").replace('"', "")
    porta_extraida = None
    
    if "]:" in entrada:
        partes = entrada.split("]:")
        ip_potencial = partes[0].replace("[", "")
        if partes[1].isdigit():
            porta_extraida = int(partes[1])
        entrada = ip_potencial
    elif ":" in entrada and entrada.count(":") == 1:
        partes = entrada.split(":")
        ip_potencial = partes[0]
        if partes[1].isdigit():
            porta_extraida = int(partes[1])
        entrada = ip_potencial
        
    ip_limpo = entrada.replace("[", "").replace("]", "")
    try:
        ip_objeto = ipaddress.ip_address(ip_limpo)
        return ip_objeto, ip_objeto.version, porta_extraida
    except ValueError:
        return None, None, None

async def obter_reverse_dns(ip):
    try:
        loop = asyncio.get_event_loop()
        nome_host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, str(ip))
        return nome_host
    except Exception:
        return ""

async def inspecionar_certificado_ssl(ip, versao_ip, porta=443):
    try:
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        familia = socket.AF_INET if versao_ip == 4 else socket.AF_INET6
        
        loop = asyncio.get_event_loop()
        conexao = loop.open_connection(str(ip), porta, ssl=contexto, family=familia)
        reader, writer = await asyncio.wait_for(conexao, timeout=2.0)
        
        aba_ssl = writer.get_extra_info('ssl_object')
        cert = aba_ssl.getpeercert(binary_form=False)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        
        if cert:
            subjacente = dict(x[0] for x in cert.get('subject', []))
            emissor = dict(x[0] for x in cert.get('issuer', []))
            return {
                "CN": subjacente.get('commonName', ''),
                "Org": subjacente.get('organizationName', ''),
                "Emissor": emissor.get('commonName', ''),
                "SANs": [alt[1] for alt in cert.get('subjectAltName', []) if alt[0] == 'DNS']
            }
    except Exception:
        pass
    return None

async def verificar_tor(session, ip):
    try:
        async with session.get("https://check.torproject.org/torbulkexitlist", timeout=3) as resp:
            if resp.status == 200:
                return str(ip) in await resp.text()
    except Exception: pass
    return False

async def escanear_porta(ip, versao_ip, port):
    try:
        familia = socket.AF_INET if versao_ip == 4 else socket.AF_INET6
        conectar = asyncio.open_connection(str(ip), port, family=familia)
        reader, writer = await asyncio.wait_for(conectar, timeout=1.5)
        try:
            banner = await asyncio.wait_for(reader.read(100), timeout=1.0)
            banner_str = banner.decode('utf-8', errors='ignore').replace('\n', ' ').strip()
            if not banner_str: banner_str = "Conexao Ativa (Handshake TCP Completo)"
        except asyncio.TimeoutError:
            banner_str = "Porta Aberta (Sem Banner de Resposta)"
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return port, banner_str
    except Exception: 
        return port, None

async def puxar_geo(session, ip):
    try:
        async with session.get(f"https://ipapi.co/{str(ip)}/json/", timeout=5) as r:
            if r.status == 200: return await r.json()
    except Exception: pass
    return None

def analisar_heuristica_vpn(org, isp):
    texto = f"{org} {isp}".lower()
    gatilhos = ['ovh', 'digitalocean', 'amazon', 'aws', 'google cloud', 'linode', 'hetzner', 
                'microsoft', 'azure', 'vpn', 'proxy', 'hosting', 'server', 'datacenter', 
                'cloudflare', 'vultr', 'leaseweb', 'nordvpn', 'expressvpn']
    for g in gatilhos:
        if g in texto: return True
    return False

async def core_busca(agent, lang):
    os.system('clear')
    entrada = input(GREEN + f"[+] {TXT[lang]['input_ip']}\n» ")
    ip_obj, versao, porta_detectada = limpar_e_validar_ip(entrada)
    
    if not ip_obj:
        sys.stdout.write(f"\n{GREEN}[-] {TXT[lang]['invalid_ip']}\n\n")
        input("Pressione Enter para retornar...")
        return

    if porta_detectada:
        portas_alvo = [porta_detectada]
    else:
        portas_alvo = [21, 22, 80, 443, 8080]

    os.system('clear')
    sys.stdout.write(f"{BOLD_GREEN}--- {TXT[lang]['scanning'].upper()} ---\n\n")

    async with aiohttp.ClientSession() as session:
        tarefas_portas = [escanear_porta(ip_obj, versao, p) for p in portas_alvo]
        resultados = await asyncio.gather(
            puxar_geo(session, ip_obj),
            verificar_tor(session, ip_obj),
            obter_reverse_dns(ip_obj),
            inspecionar_certificado_ssl(ip_obj, versao),
            *tarefas_portas
        )
        geo, tor, rdns, ssl_cert = resultados[0], resultados[1], resultados[2], resultados[3]
        portas_res = resultados[4:]

    if geo is None: 
        geo = {}

    print(BOLD_GREEN + TXT[lang]['sec_geo'])
    print(GREEN + f" * {TXT[lang]['lbl_ip']:<30} {str(ip_obj)}")
    print(f" * {TXT[lang]['lbl_type']:<30} IPv{versao}")
    print(f" * {TXT[lang]['lbl_asn']:<30} {geo.get('asn', '')}")
    print(f" * {TXT[lang]['lbl_isp']:<30} {geo.get('org', '')}")
    
    cidade = geo.get('city', '')
    pais = geo.get('country_name', '')
    cod_pais = geo.get('country_code', '')
    loc_completa = f"{cidade}, {pais} ({cod_pais})" if cidade or pais else ""
    print(f" * {TXT[lang]['lbl_loc']:<30} {loc_completa}")
    print(f" * {TXT[lang]['lbl_zip']:<30} {geo.get('postal', '')}")
    print(f" * {TXT[lang]['lbl_tz']:<30} {geo.get('timezone', '')}")
    
    lat = geo.get('latitude')
    lon = geo.get('longitude')
    maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else ""
    print(f" * {TXT[lang]['lbl_maps']:<30} {maps_link}")

    print("\n" + BOLD_GREEN + TXT[lang]['sec_ident'])
    print(GREEN + f" * {TXT[lang]['lbl_rdns']:<30} {rdns}")
    status_tor = TXT[lang]['tor_yes'] if tor else TXT[lang]['tor_no']
    print(f" * {TXT[lang]['lbl_tor']:<30} {status_tor}")
    
    org_name = geo.get('org', '')
    is_vpn = analisar_heuristica_vpn(org_name, org_name) if org_name else False
    status_vpn = TXT[lang]['vpn_yes'] if is_vpn else TXT[lang]['vpn_no']
    print(f" * {TXT[lang]['lbl_vpn']:<30} {status_vpn}")

    if ssl_cert:
        print("\n" + BOLD_GREEN + TXT[lang]['sec_ssl'])
        print(GREEN + f" * {TXT[lang]['ssl_cn']:<30} {ssl_cert['CN']}")
        print(f" * {TXT[lang]['ssl_org']:<30} {ssl_cert['Org']}")
        print(f" * {TXT[lang]['ssl_issuer']:<30} {ssl_cert['Emissor']}")
        if ssl_cert['SANs']:
            print(f" * {TXT[lang]['ssl_subs']}")
            for alt in ssl_cert['SANs'][:4]:
                print(f"   |-- {alt}")

    print("\n" + BOLD_GREEN + TXT[lang]['sec_ports'])
    abertas = 0
    for p, banner in portas_res:
        if banner:
            abertas += 1
            print(GREEN + f" * [Porta {p}]: {TXT[lang]['port_open']} -> {banner}")
    if abertas == 0:
        print(GREEN + f" * {TXT[lang]['no_ports']}")

    print("\n" + BOLD_GREEN + "="*65 + RESET)
    input(GREEN + "Pressione Enter para voltar ao menu principal...")

async def main():
    sherlock_ascii = r"""
                         .-----,_
                        /        \
                (      /   ,-----'
               )      /   /
              ( )    /   /  ____  _   _ _____ ____  _     ___       ___ ____
             .-''-. /   /  / ___|| | | | ____|  _ \| |   / _ \     |_ _|  _ \
            /  __  .   /   \___ \| |_| |  _| | |_) | |  | | | |_____| || |_) |
           |  /  \    /     ___) |  _  | |___|  _ <| |__| |_| |_____| ||  __/
           |  \\__/  /     |____/|_| |_|_____|_| \_\_____\___/     |___|_|
            \       /
             '-...-'
                                           .:-+*##*++=--::....::--=++*##*+-:.                                           
                                      .=*#*=-.                            .-=*#*=.                                      
                                  .+%#=.                                        .=#%+.                                  
                               -##=.                                                .=##-                               
                           .-#*-                                                        -*#-.                           
                         :**-                                                              -**:                         
                       =%+                                                                    +%=                       
                     +%=                          .-=*%#*%%%%+:                                 =%+                     
                   =#-                           =%%%%%%%%%%%%%%#=:                               -#=                   
                 :#=                             *%%@@@@@@@@@@@@%%%%*.                              =#:                 
                *#.                            =%%%%@@@@@@@@@@@@%%%%%%#.                             .#*                
              -%=                            .*%%%%@@@@@@@@@@@@@@@@%%%%%.                              =%-              
             +#.                             =%%%@@@@@@@@@@@@@@@@@@@@%%%%%%%%#=.                        .#+             
           .+*.                             .*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%                         .*+.           
          .*+                               .#%@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%=                           +*.          
          *+                                -%%@@@@@@@@@@@@@@@@@@@@@@@@@%+--.                               +*          
         +*                                :*%%@@@@@@@@@@@@@@@@@@@@@@@@@%#:                                  *+         
        =#.                              -#%%%%@@@@@@@@@@@@@@@@@@@@@@@@@%%%=                                 .#=        
       .%-                              -%%%%%**%@@@@@@@@@@@@@@@@@@@@@@@%%%*.                                 -%.       
       #*                                      .%%%%@@@@@@@@@@@@@@@@@@@@%-                                     *#       
      -%.                                       =%%%@@@@@@@@@@@@@@@@@%%%%*                                     .%-      
      *+                                        =%%%@@@@@@@@@@@@@@@@@%%%%.                                      +*      
     :#:                                     :*#%%%%@@@@@@@@@@@@@@@@@%%%*.                                      :#:     
     =#                                     -%%%%@@@@@@@@@@@@@@@%%%%%%%%%:                                       #=     
     *+                                    =%%%@@@@@@@@@@@@@@@%%%*=+***+:                                        +*     
     *=                                  :%%%%@@@@@@@@@@@@@@@%%%%-                                               =*     
    .*=                               :*%%%%@@@@@@@@@@@@@@@@@%%*                                                 =*.    
    .*=                             -#%%@@@@@@@@@@@@@@@@@@@@@%%%%-         ..                                    =*.    
     *=                           -#%%@@@@@@@@@@@@@@@@@@@@@@@@@@%%-       .+**%%%=.     --.                      =*     
     *+                          +%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@%%=            .*%%*.  *%%%#***-                 +*     
     =#                         *%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#:             *%%= -%%%@%%%%%:                #=     
     :#:                       -%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#:             -%%%=*%@@@@@@%%-               :#:     
      *+                      .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%*.             .%%%@@@@@@@@@%%+               +*      
      -%.                     +%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%*.             =%%@@@@@@@@@%%+              .%-      
       #*                    :#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%+.             :#%%%@@@@@@%%:              *#       
       .%-                   =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%+.              *%%@@@%%%%-              -%.       
        =#.                 .*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%-             -%%@@@%%%=              .#=        
         +*                 :#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%#.            *%@@@%%#.              *+         
          *+                =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%+         -#%%@@@%%=              +*          
          .*+              .*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%*:     :#%@@@@@@%%:             +*.          
           .+*.            :#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%+. .*%%%@@@@@@%%=           .*+.           
             +#.           =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%#*%%%%%@@@@@@%%+          .#+             
              -%=          =%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%*.        =%-              
                *#.       .*%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%-      .#*                
                 :#=      .#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%=     =#:                 
                   =#-    :#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%*.   -#=                   
                     +%=  -%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%=   =%+                     
                       =%**%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%=  +%=                       
                         :*%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%#--**:                         
                           .-#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%###-.                           
                               -#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-                               
                                  .+%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%+.                                  
                                      .=*#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#*=.                                      
                                           .:-+*%%@@@@@@@@@@@@@@@@@@@@%%*+-:.                                           
                                                      ...::::::...
             """

    os.system('clear')
    sys.stdout.write(GREEN + "╔════════════════════════════════════════╗\n")
    sys.stdout.write("║           WELCOME SHERLO-IP            ║\n")
    sys.stdout.write("║                 V.1.0                  ║\n")
    sys.stdout.write("╚════════════════════════════════════════╝\n")
    
    agent = input(f"{GREEN}» Agent Name: ")
    lang = input(f"{GREEN}» Language (PT/EN): ").strip().upper()
    
    if lang not in ["PT", "EN"]: lang = "PT"
    if not agent.strip(): agent = "Agent_Sherlock"
    
    await exibir_carregamento()
    
    while True:
        os.system('clear')
        sys.stdout.write(GREEN + "================================================================\n")
        sys.stdout.write(GREEN + sherlock_ascii + "\n")
        sys.stdout.write(GREEN + "================================================================\n")
        sys.stdout.write(f"Copyright mrmaestrox V.1.0\n====\n[Agent: {agent}]\n\n")
        
        await digitar_opcao("[1] SEARCH IP", 0.015)
        await digitar_opcao("[2] EXIT", 0.015)
        sys.stdout.write("\n")
        
        opcao = input(GREEN + "» ").strip()
        
        if opcao == "1":
            await core_busca(agent, lang)
            await exibir_carregamento()
        elif opcao == "2":
            os.system('clear')
            sys.exit(0)
        else:
            sys.stdout.write(f"\n{GREEN}[-] {TXT[lang]['invalid_opt']}\n")
            await asyncio.sleep(1.2)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
