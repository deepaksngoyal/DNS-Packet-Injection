all: clean dnsinject dnsdetect

dnsinject: dnsinject.c
	gcc -g dnsinject.c -lnet -lpcap -lresolv -o dnsinject

dnsdetect: dnsdetect.c
	gcc -g dnsdetect.c -lnet -lpcap -lresolv -o dnsdetect

clean:
	rm -f dnsinject dnsdetect
