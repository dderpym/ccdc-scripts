HOST ?= all
CTL := ./scripts/ccdcctl
.PHONY: ping init ssh listeners firewall baseline monitor test
ping:
	$(CTL) ping $(HOST)
init:
	$(CTL) init $(HOST)
ssh:
	$(CTL) ssh configure $(HOST)
listeners:
	$(CTL) listeners $(HOST)
firewall:
	$(CTL) firewall configure $(HOST)
baseline:
	@status=0; $(CTL) ssh baseline $(HOST) || status=1; \
	$(CTL) firewall baseline $(HOST) || status=1; exit $$status
monitor:
	$(CTL) monitor --host $(HOST)
test:
	python3 -m unittest discover -s tests -v
