PYTHON   := python3
SNIFFER  := sniffer/main.py
SRC      := sniffer

IFACE    ?=
FILTER   ?=

.PHONY: run install check clean

run:
	sudo $(PYTHON) $(SNIFFER) $(if $(IFACE),-i $(IFACE),) $(if $(FILTER),-f "$(FILTER)",)

install:
	pip install scapy textual
	sudo pip install scapy textual

check:
	$(PYTHON) -m py_compile \
		$(SRC)/main.py \
		$(SRC)/core/captura.py \
		$(SRC)/core/filter.py \
		$(SRC)/core/packet_parser.py \
		$(SRC)/ui/ui.py \
		$(SRC)/ui/screens/main_screen.py \
		$(SRC)/ui/widgets/filter_bar.py \
		$(SRC)/ui/widgets/packet_table.py \
		$(SRC)/ui/widgets/detail_panel.py
	@echo "All files OK"

clean:
	sudo find $(SRC) -type d -name __pycache__ -exec rm -rf {} +
	sudo find $(SRC) -name "*.pyc" -delete
