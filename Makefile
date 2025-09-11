USERBINS=af_xdp_lat
BPFBINS=af_xdp_kern.o
ALL: $(BPFBINS) $(USERBINS)

$(BPFBINS): %.o: %.c
	clang -target bpf -O2 -c -g -o $@ $<

$(USERBINS): %: %.c utils.c
	gcc -Wall -Werror -g -o $@ $^ -lxdp -lbpf

.PHONY: clean
clean:
	rm -f $(BPFBINS) $(USERBINS)
