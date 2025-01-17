CC = gcc

WARNFLAGS = -pedantic -pedantic-errors -Wall -Wextra -Wpedantic -Werror \
		-Wdouble-promotion -Wnull-dereference -Winit-self -Wuninitialized \
		-Wformat=2 -Wformat-overflow=2 -Wformat-signedness -Wformat-truncation=2 \
		-Wmissing-include-dirs -Wunused -Wunreachable-code -Wfloat-equal \
		-Wuseless-cast -Wstrict-overflow=5 -Wstringop-overflow=4 \
		-Wsuggest-attribute=pure -Wsuggest-attribute=const -Wsuggest-attribute=noreturn \
		-Wsuggest-attribute=returns_nonnull -Wsuggest-attribute=cold \
		-Walloc-size -Walloc-zero -Walloca -Wcalloc-transposed-args \
		-Warith-conversion -Wconversion -Wfloat-conversion -Wshadow \
		-Wduplicated-branches -Wduplicated-cond -Wunsafe-loop-optimizations \
		-Wundef -Wbad-function-cast -Wcast-qual -Wcast-align=strict \
		-Wwrite-strings -Wcompare-distinct-pointer-types -Wconversion \
		-Wdangling-else -Wlogical-op -Waggregate-return -Wstrict-prototypes \
		-Wold-style-declaration -Wold-style-definition -Wmissing-prototypes \
		-Wmissing-variable-declarations -Wredundant-decls -Wnested-externs \
		-Winline -Wdisabled-optimization -Wvla \

CFLAGS = -std=c99 -fPIC -Og -fsanitize=undefined,address -fstack-protector-strong \
		$(shell pkg-config --cflags luajit openssl) $(WARNFLAGS)
LDFLAGS = -shared -fPIC \
		$(shell pkg-config --libs luajit openssl)

OBJS = private.o compat.o lunarssl.o bio.o bn.o

all: lunarssl.so
.PHONY: all clean check

compile_flags.txt: Makefile
	echo $(CFLAGS) | tr ' ' '\n' >compile_flags.txt

lunarssl.so: $(OBJS) | compile_flags.txt
	$(CC) -o $@ -shared -fPIC $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f lunarssl.so
	rm -f $(OBJS)

check: compile_flags.txt
	clang-tidy -p . $(OBJS:.o=.c) -checks='bugprone-*,clang-analyzer-*,performance-*,portability-*,misc-*' -header-filter='src/*'
