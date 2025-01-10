CC = clang

WARNFLAGS = -Wall -Wextra -Werror -Wpedantic
CFLAGS = -fPIC -Og -fsanitize=undefined,address -fstack-protector-strong \
		$(shell pkg-config --cflags luajit openssl) $(WARNFLAGS) \
		-DCOMPAT53_PREFIX=lua53 
LDFLAGS = -shared -fPIC \
		$(shell pkg-config --libs luajit openssl)

OBJS = private.o lunarssl.o bio.o bn.o
OBJS_EXTRA = vendor/compat-5.3.o

all: lunarssl.so

lunarssl.so: $(OBJS) $(OBJS_EXTRA)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -shared -fPIC $^ -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f lunarssl.so
	rm -f $(OBJS) $(OBJS_EXTRA)

check:
	clang-tidy -p . $(OBJS:.o=.c) -checks='bugprone-*,clang-analyzer-*,performance-*,portability-*,misc-*' -header-filter='.*'