
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
| `make run` | Executa e abre o ecrã de configuração |
| `make run FILTER="tcp port 443"` | Executa com um filtro BPF pré-definido |
| `make run COUNT=100` | Executa em Log mode com limite de pacotes pré-definido |
| `make install` | Instala as dependências |
| `make check` | Verifica a sintaxe de todos os ficheiros fonte |
| `make clean` | Remove ficheiros `__pycache__`, `.pyc` e a pasta `captures/` |

### Manualmente

```bash
sudo python3 sniffer/main.py [opções]
```

| Opção | Descrição |
|-------|-----------|
| `-f`, `--filter` | Filtro BPF inicial (ex: `tcp port 80`, `udp`, `icmp`). Se fornecido, o ecrã de setup é ignorado. |
| `-c`, `--count N` | Número máximo de pacotes a capturar. Se fornecido, ativa o Log mode e ignora o ecrã de setup. |

---

## Fluxo de utilização

Ao arrancar, o sniffer apresenta um **ecrã de configuração** onde é possível escolher a interface e o modo de captura antes de iniciar. Se `-f` ou `-c` forem fornecidos na linha de comandos, o ecrã de setup é ignorado e a captura começa de imediato.

1. **Ecrã de setup** — seleciona a interface de rede (dropdown com interfaces disponíveis), o modo de captura (live ou log) e, em Log mode, o número de pacotes a capturar.
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

Ecrã de resumo:

| Tecla | Ação |
|-------|------|
| `q` / `Q` | Sair da aplicação |

---

## Funcionalidades

- Ecrã de configuração inicial para selecionar a interface, o modo de captura e o limite de pacotes
- Interface Textual TUI interativa com tabela de pacotes em tempo real e painel de detalhes
- Layout dividido: barra de filtros, tabela de pacotes, painel de detalhes
- Protocolos com cores: TCP, UDP, ICMP, ARP, DNS, HTTP, IPv4, IPv6
- Ordem de deteção de protocolos: ARP > HTTP > DNS > ICMP > TCP > UDP > IPv4/IPv6
- IP e porta de origem/destino; src/dst IPv6 apresentados corretamente
- Descodificação de flags TCP (SYN, ACK, FIN, RST, PSH, URG)
- Extração do nome de queries DNS
- Extração de método, host e caminho HTTP
- Barra de filtro unificada — um campo filtra por protocolo, IP, MAC ou interface (substring sem distinção de maiúsculas/minúsculas); campo separado para expressão BPF com botão Aplicar
- Filtro com debounce de 250 ms para manter a resposta fluída durante a captura
- Apresentação limitada aos 500 pacotes correspondentes mais recentes
- Validação do filtro BPF no arranque via `tcpdump -d`; filtragem BPF por pacote via libpcap offline (`pcap_offline_filter`)
- Filtro BPF pode ser atualizado em tempo real pela UI; o processo de captura reinicia com o novo filtro ao nível do kernel
- **Parar captura (`q`)** — termina a captura permanentemente; em Log mode, guarda automaticamente os pacotes em JSON na pasta `captures/`; navega para o ecrã de resumo com estatísticas
- **Pausar / Retomar captura (`p`)** — alterna entre pausa e captura ativa sem terminar a sessão; status visual `⏸ PAUSED` (amarelo) quando pausado e `● LIVE` (verde) quando a capturar; pacotes recebidos durante pausa são descartados silenciosamente; o estado de pausa é preservado ao reiniciar a captura com novo filtro BPF
- **Exportar PCAP (`e`)** — exporta os pacotes capturados para um ficheiro `.pcap` na pasta `captures/` com o nome `capture_YYYYMMDD_HHMMSS.pcap`
- Deteção e anotação de fragmentos IPv4 (FRAG-FIRST, FRAG+NB, FRAG-LAST); painel de detalhes agrupa fragmentos relacionados
- Painel de detalhes com campos por camada traduzidos para português e bytes raw do pacote
- Ecrã de resumo com estatísticas (total de pacotes, protocolos, bytes) após parar a captura; em Log mode, exportação automática para JSON

---

## Estrutura do Projeto

```
.
├── Makefile
├── sniffer/
│   ├── main.py
│   ├── core/
│   │   ├── captura.py        # thread de captura de pacotes (Scapy)
│   │   ├── filter.py         # validação de filtros BPF e BpfMatcher (libpcap)
│   │   └── packet_parser.py  # pacote raw → dict
│   └── ui/
│       ├── ui.py             # ponto de entrada da app Textual
│       ├── sniffer.tcss      # layout e estilos
│       ├── screens/
│       │   ├── setup_screen.py   # ecrã de configuração inicial (interface + modo + limite)
│       │   ├── main_screen.py    # ecrã principal de captura
│       │   └── summary_screen.py # ecrã de resumo e estatísticas
│       └── widgets/
│           ├── filter_bar.py        # filtro unificado (protocolo / IP / MAC / interface) + filtro BPF
│           ├── interface_selector.py # dropdown com interfaces de rede disponíveis
│           ├── packet_table.py      # lista de pacotes em tempo real (DataTable)
│           └── detail_panel.py      # camadas por pacote, fragmentos e bytes raw
└── README.md
```
