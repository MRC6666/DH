server: server.c DH.o aes.o
	gcc -w -O server.c DH.o aes.o -lgmp -o server   
DH.o: DH.c DH.h
	gcc -c DH.c -o DH.o
aes.o: aes.c aes.h
	gcc -c aes.c -o aes.o
clean:
	rm *.o server
