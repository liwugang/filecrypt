SRCS := filecrypt.c algs/*.c

all: filecrypt
	
filecrypt: $(SRCS)
	gcc -o filecrypt -g $(SRCS)

clean:
	rm filecrypt