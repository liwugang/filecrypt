SRCS := filecrypt.c algs/*.c

CFLAGS := -lcrypto # -g -DDEBUG

all: filecrypt

filecrypt: $(SRCS)
	gcc -o filecrypt $(SRCS) $(CFLAGS) -g

clean:
	rm filecrypt