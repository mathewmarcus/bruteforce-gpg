bruteforce-gpg: src/main.c
	gcc -pthread -l gpgme -o bruteforce-gpg src/main.c
clean:
	rm --force bruteforce-gpg
