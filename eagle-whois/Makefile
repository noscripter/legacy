# eagle-whois MakeFile  
# Written by Hypsurus <hypsurus@mail.ru> 
# 09/04/2015

# Handle the install/Uninstall stuff
BIN=$(wildcard *.c)
CONF=$(wildcard conf/*.conf)
PREFIX="/usr/local"
MAN="/share/man/man1/"
BINDIR="/bin/"


all:
	$(CC) $(CFLAGS) $(BIN) -o $(BIN:.c=)

install: all
	@mkdir -p ${PREFIX}${MAN}
	@mkdir -p ${PREFIX}${BINDIR}

	@install -Dm775 $(BIN:.c=) ${PREFIX}${BINDIR}${BIN:.c=}
	@install -Dm444 man/$(BIN:.c=).1 ${PREFIX}${MAN}$(BIN:.c=).1
	@install -Dm444 $(CONF) /etc/${CONF}

uninstall: 
	@rm -f ${PREFIX}${BINDIR}${BIN:.c=}
	@rm -f ${PREFIX}${MAN}$(BIN:.c=).1
	@rm -f /etc/${CONF}

# Debug
debug: CFLAGS += -DDEBUG -ggdb
debug: all

# GeoIP 
geoip: CFLAGS += -lGeoIP -DGEOIP
geoip: all

clean:
	rm -f $(BIN:.c=)

.PHONY: all install uninstall clean geoip
