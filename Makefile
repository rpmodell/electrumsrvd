CC=cc
CFLAGS=-std=c99 -D_DEFAULT_SOURCE -O2 -Wall -Wstrict-prototypes -pedantic -I/usr/local/include/
LDFLAGS=-lcurl -lpthread -lleveldb -lcrypto -lssl -lm -L/usr/local/lib/

SOURCES_DIR=src/

OBJS=shared.o ujson.o hashes_vec.o block_sync.o bitcoin_rpc.o bitcoin_common.o bitcoin_p2p.o txdb.o merkle.o util.o mempool.o logging.o config.o electrum_rpc.o main.o
TARGET=electrumsrvd

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

shared.o: $(SOURCES_DIR)/shared.c $(SOURCES_DIR)/shared.h
	$(CC) $(CFLAGS) -c -o $@ $<

ujson.o: $(SOURCES_DIR)/ujson.c $(SOURCES_DIR)/ujson.h
	$(CC) $(CFLAGS) -c -o $@ $<

hashes_vec.o: $(SOURCES_DIR)/hashes_vec.c $(SOURCES_DIR)/hashes_vec.h
	$(CC) $(CFLAGS) -c -o $@ $<

block_sync.o: $(SOURCES_DIR)/block_sync.c $(SOURCES_DIR)/block_sync.h
	$(CC) $(CFLAGS) -c -o $@ $<

bitcoin_common.o: $(SOURCES_DIR)/bitcoin_common.c $(SOURCES_DIR)/bitcoin_common.h
	$(CC) $(CFLAGS) -c -o $@ $<

bitcoin_rpc.o: $(SOURCES_DIR)/bitcoin_rpc.c $(SOURCES_DIR)/bitcoin_rpc.h
	$(CC) $(CFLAGS) -c -o $@ $<

bitcoin_p2p.o: $(SOURCES_DIR)/bitcoin_p2p.c $(SOURCES_DIR)/bitcoin_p2p.h
	$(CC) $(CFLAGS) -c -o $@ $<

txdb.o: $(SOURCES_DIR)/txdb.c $(SOURCES_DIR)/txdb.h
	$(CC) $(CFLAGS) -c -o $@ $<

merkle.o: $(SOURCES_DIR)/merkle.c $(SOURCES_DIR)/merkle.h
	$(CC) $(CFLAGS) -c -o $@ $<

util.o: $(SOURCES_DIR)/util.c $(SOURCES_DIR)/util.h
	$(CC) $(CFLAGS) -c -o $@ $<

mempool.o: $(SOURCES_DIR)/mempool.c $(SOURCES_DIR)/mempool.h
	$(CC) $(CFLAGS) -c -o $@ $<

logging.o: $(SOURCES_DIR)/logging.c $(SOURCES_DIR)/logging.h
	$(CC) $(CFLAGS) -c -o $@ $<

config.o: $(SOURCES_DIR)/config.c $(SOURCES_DIR)/config.h
	$(CC) $(CFLAGS) -c -o $@ $<

electrum_rpc.o: $(SOURCES_DIR)/electrum_rpc.c $(SOURCES_DIR)/electrum_rpc.h
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: $(SOURCES_DIR)/main.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	@rm -f $(TARGET) $(OBJS)

.PHONY: install
install:
	install -m 0755 ./$(TARGET) /usr/local/bin/ 
	install -m 0664 -b ./etc/$(TARGET).conf /usr/local/etc/
	-install -m 0664 ./$(TARGET).1 /usr/local/share/man/man1/
	-install -m 0664 ./$(TARGET).1 /usr/local/man/man1/
	-install -m 0664 ./$(TARGET).conf.1 /usr/local/share/man/man1/
	-install -m 0664 ./$(TARGET).conf.1 /usr/local/man/man1/
