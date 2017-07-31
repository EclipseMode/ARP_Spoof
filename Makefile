make : main.c
	gcc -o main main.c -lpcap -w

clean : 
	rm -f main

