
CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra

all: drinkme

drinkme: drinkme.c
	$(CC) $(CFLAGS) -o drinkme drinkme.c

clean:
	rm drinkme
