TARGETS = fsx
HEADERS = fsx_struct.h parsing_helper.h
INCLUDE_DIRS = -I/usr/include/$(shell uname -m)-linux-gnu -I .
IFACE = lo

all: $(TARGETS)
.PHONY: all

$(TARGETS): % : %_kern.o 

%_kern.o :%_kern.c $(HEADERS)
	clang \
		-target bpf \
		$(INCLUDE_DIRS)  \
		-g \
		-w \
		-O2 -o $@ -c $<

yaml_reader :
	clang -o yaml_reader yaml_reader.c -lbpf

load: fsx_kern.o
	sudo ip link set dev $(IFACE) xdp obj fsx_kern.o section xdp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf none /sys/fs/bpf
#sudo bpftool map pin name syn_lru_hash_map /sys/fs/bpf/syn_lru_hash_map

detach:
	sudo ip link set dev $(IFACE) xdp off
#sudo rm -f /sys/fs/bpf/syn_lru_hash_map
#sudo rm -f /sys/fs/bpf/syn_size_oldtime


clean:
	- rm *.o 
	- rm -f /sys/fs/bpf/$(TARGETS)