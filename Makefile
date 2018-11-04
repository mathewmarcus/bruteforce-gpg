bruteforce-gpg: src/main.c bruteforce_gpg.o
	gcc -pthread -l gpgme -o bruteforce-gpg src/main.c bruteforce_gpg.o
bruteforce_gpg.o: src/bruteforce_gpg.c src/bruteforce_gpg.h
	gcc -c src/bruteforce_gpg.c -o bruteforce_gpg.o
clean:
	rm --force bruteforce-gpg bruteforce_gpg.o
