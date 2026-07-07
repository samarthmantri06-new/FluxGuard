# ==============================================================================
# FluxGuard — build / attach / pin / run helpers  (Linux only)
#
# The kernel object is built with clang/LLVM targeting BPF. Attaching XDP and
# pinning maps requires root. This Makefile consolidates the per-phase runbooks
# (docs/runbooks/phaseNN-*.txt) into single commands.
#
# Quick start (netns lab):
#   make build          # compile fluxguard_kern.o
#   sudo make lab-up     # create netns topology (client/fluxguard/backend)
#   sudo make attach IFACE=veth-fg   # attach XDP + pin every map
#   sudo make run-brain              # start the control loop
#
# Production (real NIC):
#   make build
#   sudo make attach IFACE=eth0 XDP_MODE=xdpdrv
# ==============================================================================

ARCH        := $(shell uname -m)
CLANG       ?= clang
PYTHON      ?= python3

SRC_DIR     := src
TEST_DIR    := tests

KERN_SRC    := $(SRC_DIR)/fluxguard_kern.c
KERN_OBJ    := $(SRC_DIR)/fluxguard_kern.o

IFACE       ?= eth0
XDP_MODE    ?= xdpgeneric          # xdpgeneric (VM/VirtualBox) | xdpdrv (real NIC)
NETNS       ?= fluxguard
PIN_DIR     ?= /sys/fs/bpf/$(NETNS)
SEC         ?= xdp

# Every map the kernel program defines; must match names referenced in Python.
MAPS := blacklist_map meter_map allowlist_map rate_map \
        blacklist_map_v6 meter_map_v6 allowlist_map_v6 rate_map_v6 \
        global_counter_map global_rate_map proto_filter_map event_ringbuf

.PHONY: help build verify attach detach pin run-brain run-dashboard run-api test clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?#' $(MAKEFILE_LIST) | sed 's/:.*#/\t/' || true
	@echo "Vars: IFACE=$(IFACE) XDP_MODE=$(XDP_MODE) NETNS=$(NETNS) PIN_DIR=$(PIN_DIR)"

build: $(KERN_OBJ)   # compile the XDP kernel object

$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) -O2 -g -Wall -target bpf \
		-I/usr/include/$(ARCH)-linux-gnu \
		-c $(KERN_SRC) -o $(KERN_OBJ)
	@echo "Built $(KERN_OBJ)"

verify: $(KERN_OBJ)   # dump sections to sanity-check maps + xdp prog
	llvm-objdump -h $(KERN_OBJ) | grep -E "maps|xdp" || true

attach: $(KERN_OBJ)   # load+attach XDP on IFACE and pin all maps under PIN_DIR
	mkdir -p $(PIN_DIR)
	ip link set dev $(IFACE) $(XDP_MODE) obj $(KERN_OBJ) sec $(SEC)
	@for m in $(MAPS); do \
		bpftool map show name $$m 2>/dev/null | head -1 | \
		awk -v d=$(PIN_DIR) -v n=$$m '{print $$1}' | tr -d ':' | \
		xargs -I{} bpftool map pin id {} $(PIN_DIR)/$$m 2>/dev/null && \
		echo "pinned $$m" || echo "skip $$m (already pinned or absent)"; \
	done
	@echo "Attached $(SEC) on $(IFACE) ($(XDP_MODE)); maps pinned in $(PIN_DIR)"

detach:   # remove XDP program from IFACE and unpin maps
	ip link set dev $(IFACE) xdpgeneric off 2>/dev/null || true
	ip link set dev $(IFACE) xdpdrv off 2>/dev/null || true
	rm -rf $(PIN_DIR)
	@echo "Detached XDP from $(IFACE); removed $(PIN_DIR)"

run-brain:   # start the control loop (reads pinned maps)
	$(PYTHON) $(SRC_DIR)/fluxguard_brain.py --netns $(NETNS) --poll-interval 0.2 \
		--cooldown-sec 30 --allowlist-refresh-sec 5 --verbose

run-dashboard:   # read-only TUI
	$(PYTHON) $(SRC_DIR)/fluxguard_dashboard.py \
		--metrics-url http://127.0.0.1:9090/metrics \
		--ringbuf-path $(PIN_DIR)/event_ringbuf --refresh 2.0

run-api:   # Flask REST API
	$(PYTHON) $(SRC_DIR)/fluxguard_api.py

test:   # pure-python unit tests (no root, no BPF, runs anywhere)
	$(PYTHON) -m pytest $(TEST_DIR) -v

clean:   # remove build artifacts
	rm -f $(KERN_OBJ) *.ll *.bc
	@echo "Cleaned build artifacts"
