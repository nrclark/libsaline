default: crypto_box.so

%.o: %.c
	gcc -c -fpic $< -o $@

crypto_box.so: crypto_box_wrapper.o crypto_scalarmult_wrapper.o
	gcc -shared -o $@ $^ -lsodium

