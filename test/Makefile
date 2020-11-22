default: libcrypto.so

%.o: %.c
	gcc -c -fpic $< -o $@

OBJS := crypto_box_wrapper.o crypto_scalarmult_wrapper.o crypto_sign_wrapper.o
libcrypto.so: $(OBJS)
	gcc -shared -o $@ $^ -lsodium

clean:
	rm -f *.o *.so