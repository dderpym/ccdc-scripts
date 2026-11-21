HOST ?= all
CTL := ./ccdcctl
.PHONY: ping init scan listeners firewall integrity lse baseline
ping:
	$(CTL) ping $(HOST)
init:
	$(CTL) init $(HOST)
scan:
	$(CTL) scan $(HOST)
listeners:
	$(CTL) listeners $(HOST)
firewall:
	$(CTL) firewall configure $(HOST)
integrity:
	$(CTL) integrity $(HOST)
lse:
	$(CTL) lse $(HOST)
baseline:
	$(CTL) firewall baseline $(HOST)
