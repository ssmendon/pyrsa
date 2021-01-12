rsa_system: rsa_system.py cryptosystem/keypair.py primes/__init__.py primes/generator.py primes/primality.py modular/operations.py
	cp rsa_system.py rsa_system
	chmod +x rsa_system

PHONY: clean
clean:
	chmod -x rsa_system
	rm rsa_system
	rm *.pub
	rm *.priv