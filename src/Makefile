CC = clang

WARNFLAGS = -Wall -Wextra -Werror -Wpedantic
CFLAGS = -fPIC -Og -fsanitize=undefined,address -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
		$(shell pkg-config --cflags luajit openssl) $(WARNFLAGS)
LDFLAGS = -shared -fPIC \
		$(shell pkg-config --libs luajit openssl)

OBJS = lunarssl.o asn1.o bn.o vendor/compat-5.3.o

all: lunarssl.so

lunarssl.so: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -shared -fPIC $^ -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f lunarssl.so
	rm -f $(OBJS)