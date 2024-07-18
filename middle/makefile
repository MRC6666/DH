middle: middle.c DH.o aes.o
	gcc -w -O middle.c DH.o aes.o -lgmp -lpcap -o middle
DH.o: DH.c DH.h
	gcc -c DH.c -o DH.o
aes.o: aes.c aes.h
	gcc -c aes.c -o aes.o
clean:
	rm *.o middle
