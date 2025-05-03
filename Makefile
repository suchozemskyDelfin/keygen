CC = gcc
CFLAGS = -Wall -O2
LDLIBS = -lssl -lcrypto

OBJS = upc_wifi_keygen.o scan.o wifisort.o passgen.o

all: keygen

keygen: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDLIBS)

upc_wifi_keygen.o: upc_wifi_keygen.c wifitypes.h scan.h wifisort.h passgen.h
scan.o: scan.c scan.h wifitypes.h
wifisort.o: wifisort.c wifisort.h wifitypes.h
passgen.o: passgen.c passgen.h wifitypes.h

clean:
	rm -f *.o keygen