client: client.c DH.o aes.o
	gcc -w -O client.c DH.o aes.o -lgmp -o client   
DH.o: DH.c DH.h
	gcc -c DH.c -o DH.o
aes.o: aes.c aes.h
	gcc -c aes.c -o aes.o
clean:
	rm *.o client
