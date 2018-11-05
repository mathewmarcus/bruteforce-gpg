bruteforce-gpg: src/main.c bruteforce_gpg.o log.o
	gcc -pthread -l gpgme -o bruteforce-gpg src/main.c bruteforce_gpg.o log.o
bruteforce_gpg.o: src/bruteforce_gpg.c src/bruteforce_gpg.h
	gcc -c src/bruteforce_gpg.c -o bruteforce_gpg.o
log.o: src/log.c src/log.h
	gcc -c src/log.c -o log.o
clean:
	rm --force bruteforce-gpg bruteforce_gpg.o log.o
install:
	install bruteforce-gpg /usr/local/bin/
