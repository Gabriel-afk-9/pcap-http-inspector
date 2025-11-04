# Pcap-http-inspector

Fazer um analisador simples de tráfego HTTP usando libpcap no Python (com a biblioteca pcapy ou python-libpcap).

O objetivo é apenas inicialmente identificar requisições HTTP (porta 80) e exibir os cabeçalhos para fins de aprendizado, com:

- Contador de Requisições por IP (Use um dicionário para contar quantas requisições cada IP origem fez).
- Extrair Cabeçalhos Específicos: Exiba apenas o Host ou User-Agent dos cabeçalhos HTTP.
- Salvar Logs em Arquivo:Grave as requisições em um arquivo .txt (sem dados sensíveis).