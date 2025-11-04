import sys
import signal
from scapy.all import sniff
from modules.capture import BPF_FILTER, INTERFACE, process_packet

def shutdown():
  print("\nEncerrando")
  sys.exit(0)

def start():
  signal.signal(signal.SIGINT, shutdown)
  signal.signal(signal.SIGTERM, shutdown)
  print(f"Iniciando sniff (filter='{BPF_FILTER}') na interface {INTERFACE or 'padrão'}. Ctrl+C para parar.")
  sniff(filter=BPF_FILTER, prn=process_packet, store=0, iface=INTERFACE)