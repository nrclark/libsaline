default: libcrypto.so

%.o: %.c
	gcc -c -fpic -Wall -Wextra -pedantic $< -o $@

OBJS := crypto_box_wrapper.o crypto_scalarmult_wrapper.o \
		crypto_sign_wrapper.o crypto_secretbox_wrapper.o \
		crypto_stream_wrapper.o crypto_auth_wrapper.o \
		crypto_onetimeauth_wrapper.o crypto_misc_wrapper.o

libcrypto.so: $(OBJS)
	gcc -shared -o $@ $^ -lsodium

clean:
	rm -f *.o *.so