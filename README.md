
# RC TP2 — Packet Sniffer (PL55)

Sniffer de pacotes de rede desenvolvido em Python e Scapy para a unidade curricular de Redes de Computadores (2º ano).

---

## Requisitos

- Python 3.8+
- [Scapy](https://scapy.net/)
- [Textual](https://github.com/Textualize/textual)

```bash
make install
# ou manualmente: pip install scapy textual
```

São necessários privilégios de root/sudo para capturar pacotes em modo raw.

---

## Utilização

### Com Make (recomendado)

| Comando | Descrição |
|---------|-----------|
| `make run` | Executa na interface padrão (`eth0`) |
| `make run IFACE=wlan0` | Executa numa interface específica |
| `make run IFACE=eth0 FILTER="tcp port 443"` | Executa com um filtro BPF |
| `make install` | Instala as dependências |
| `make check` | Verifica a sintaxe de todos os ficheiros fonte |
| `make clean` | Remove ficheiros `__pycache__` e `.pyc` |

### Manualmente

```bash
sudo python3 sniffer/main.py [opções]
```

| Opção | Descrição |
|-------|-----------|
| `-i`, `--iface` | Interface de rede a escutar (ex: `eth0`, `wlan0`). Por defeito usa a interface do sistema. |
| `-f`, `--filter` | Filtro BPF (ex: `tcp port 80`, `udp`, `icmp`). |

---

## Fluxo de utilização

Ao arrancar, o sniffer apresenta um **ecrã de configuração** onde é possível escolher o modo de captura antes de iniciar:

1. **Ecrã de setup** — seleciona o modo de captura (live ou log) e, em Log mode, o número de pacotes a capturar.
2. **Ecrã principal de captura** — tabela de pacotes em tempo real com suporte a filtros, pausa, retoma e exportação. Use os atalhos de teclado para controlar a sessão.
3. **Ecrã de resumo** — apresentado após parar a captura (`q`), mostra estatísticas da sessão (total de pacotes, protocolos, bytes). Em Log mode, o ficheiro JSON é guardado automaticamente na pasta `captures/` ao parar.

---

## Atalhos de Teclado

Disponíveis durante a captura no ecrã principal:

| Tecla | Ação |
|-------|------|
| `q` | Parar captura e navegar para o ecrã de resumo |
| `p` | Pausar / Retomar captura |
| `e` | Exportar pacotes capturados para ficheiro PCAP |

---

## Funcionalidades

- Ecrã de configuração inicial para selecionar o modo de captura e limite de pacotes
- Interface Textual TUI interativa com tabela de pacotes em tempo real e painel de detalhes
- Layout dividido: barra de filtros, tabela de pacotes, painel de detalhes
- Protocolos com cores: TCP, UDP, ICMP, ARP, DNS, HTTP, IPv4, IPv6
- Ordem de deteção de protocolos: ARP > HTTP > DNS > ICMP > TCP > UDP > IPv4/IPv6
- IP e porta de origem/destino; src/dst IPv6 apresentados corretamente
- Descodificação de flags TCP (SYN, ACK, FIN, RST, PSH, URG)
- Extração do nome de queries DNS
- Extração de método, host e caminho HTTP
- Barra de filtro unificada — um campo filtra por protocolo, IP ou MAC (substring sem distinção de maiúsculas/minúsculas); campo separado para expressão BPF com botão Aplicar
- Filtro com debounce de 250 ms para manter a resposta fluída durante a captura
- Apresentação limitada aos 500 pacotes correspondentes mais recentes
- Validação do filtro BPF no arranque via `tcpdump -d`; filtragem BPF por pacote via libpcap offline (`pcap_offline_filter`)
- Filtro BPF pode ser atualizado em tempo real pela UI; o processo de captura reinicia com o novo filtro ao nível do kernel
- **Parar captura (`q`)** — termina a captura permanentemente; em Log mode, guarda automaticamente os pacotes em JSON na pasta `captures/`; navega para o ecrã de resumo com estatísticas
- **Pausar / Retomar captura (`p`)** — alterna entre pausa e captura ativa sem terminar a sessão; status visual `⏸ PAUSED` (amarelo) quando pausado e `● LIVE` (verde) quando a capturar; pacotes recebidos durante pausa são descartados silenciosamente; o estado de pausa é preservado ao reiniciar a captura com novo filtro BPF
- **Exportar PCAP (`e`)** — exporta os pacotes capturados para um ficheiro `.pcap` na pasta `captures/` com o nome `capture_YYYYMMDD_HHMMSS.pcap`
- Em Log mode, ecrã de resumo com estatísticas (total de pacotes, protocolos, bytes) e exportação para JSON

---

## Estrutura do Projeto

```
.
├── Makefile
├── sniffer/
│   ├── main.py
│   ├── core/
│   │   ├── captura.py        # thread de captura de pacotes (Scapy)
│   │   ├── filter.py         # validação de filtros BPF
│   │   └── packet_parser.py  # pacote raw → dict
│   └── ui/
│       ├── ui.py             # ponto de entrada da app Textual
│       ├── sniffer.tcss      # layout e estilos
│       ├── screens/
│       │   ├── setup_screen.py   # ecrã de configuração inicial (modo + limite)
│       │   ├── main_screen.py    # ecrã principal de captura
│       │   └── summary_screen.py # ecrã de resumo e estatísticas (Log mode)
│       └── widgets/
│           ├── filter_bar.py        # filtro unificado (protocolo / IP / MAC) + filtro BPF
│           ├── interface_selector.py # dropdown com interfaces de rede disponíveis
│           ├── mode_selector.py      # seletor de modo de captura + limite de pacotes
│           ├── packet_table.py      # lista de pacotes em tempo real (DataTable)
│           └── detail_panel.py      # árvore de camadas por pacote
└── README.md
```
