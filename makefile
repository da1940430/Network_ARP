all:arp

arp:main.c arp.c arp.h
	gcc main.c arp.c -o arp