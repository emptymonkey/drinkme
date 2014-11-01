
CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra

hello_world: drinkme.c
	$(CC) $(CFLAGS) -o drinkme drinkme.c

clean:
	rm drinkme
