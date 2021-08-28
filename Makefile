SRCS := filecrypt.c threads.c algs/*.c

CFLAGS := -lcrypto -pthread  -fstack-protector # -g -DDEBUG

all: filecrypt

filecrypt: $(SRCS)
	gcc -o filecrypt $(SRCS) $(CFLAGS) -O2

clean:
	rm filecrypt
