PYTHON   := python3
SNIFFER  := sniffer/main.py
SRC      := sniffer

FILTER   ?=
COUNT    ?=

.PHONY: run install check clean

run:
	sudo $(PYTHON) $(SNIFFER) $(if $(FILTER),-f "$(FILTER)",) $(if $(COUNT),-c $(COUNT),)

install:
	sudo pip install scapy textual

check:
	$(PYTHON) -m py_compile \
		$(SRC)/main.py \
		$(SRC)/core/__init__.py \
		$(SRC)/core/captura.py \
		$(SRC)/core/filter.py \
		$(SRC)/core/packet_parser.py \
		$(SRC)/ui/__init__.py \
		$(SRC)/ui/ui.py \
		$(SRC)/ui/screens/__init__.py \
		$(SRC)/ui/screens/main_screen.py \
		$(SRC)/ui/screens/setup_screen.py \
		$(SRC)/ui/screens/summary_screen.py \
		$(SRC)/ui/widgets/__init__.py \
		$(SRC)/ui/widgets/detail_panel.py \
		$(SRC)/ui/widgets/filter_bar.py \
		$(SRC)/ui/widgets/interface_selector.py \
		$(SRC)/ui/widgets/mode_selector.py \
		$(SRC)/ui/widgets/packet_table.py
	@echo "All files OK"

clean:
	sudo find $(SRC) -type d -name __pycache__ -exec rm -rf {} +
	sudo find $(SRC) -name "*.pyc" -delete
	sudo rm -rf captures
