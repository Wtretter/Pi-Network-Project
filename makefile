.PHONY: all
all: packet-sorter fallback-mode

.PHONY: clean
clean:
	rm -f bin/* packet-sorter fallback-mode

bin/%.o: src/%.c
	clang -std=c23 -c -I include $^ -o $@

packet-sorter: bin/packet-sorter.o bin/check-packet.o bin/fix-checksums.o bin/raw-network.o
	clang -std=c23 $^ -o $@

fallback-mode: bin/fallback-mode.o bin/check-packet.o bin/fix-checksums.o bin/raw-network.o
	clang -std=c23 $^ -o $@