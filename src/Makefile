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

clean:
	- rm *.o 
	- rm -f /sys/fs/bpf/$(TARGETS)


load: fsx_kern.o
	sudo ip link set dev $(IFACE) xdp obj fsx_kern.o section xdp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf none /sys/fs/bpf
#pin any maps here

detach:
	sudo ip link set dev $(IFACE) xdp off
#remove the pinned maps here