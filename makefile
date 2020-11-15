####  Makefile for compilation on Linux  ####

#OPT=-O3     # Optimization option by default
OPT=-O0

ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
endif

ADDITIONAL_SETTINGS=
ifeq "$(SET)" "EXTENDED"
    ADDITIONAL_SETTINGS=-fwrapv -fomit-frame-pointer -march=native
endif

ifeq "$(ASM)" "TRUE"
    USE_ASM=-D _ASM_
endif

ifeq "$(GENERIC)" "TRUE"
    USE_GENERIC=-D _GENERIC_
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

cc=$(COMPILER)
CFLAGS=-g -c $(OPT) -fPIC $(ADDITIONAL_SETTINGS) -D $(ARCHITECTURE) -D __LINUX__ $(USE_ASM) $(USE_GENERIC)
LDFLAGS=
ifeq "$(GENERIC)" "TRUE"
    EXTRA_OBJECTS=fp_generic.o
else
ifeq "$(ARCH)" "x64"
    EXTRA_OBJECTS=fp_x64.o fp_x64_asm.o
endif
endif
OBJECTS=kex.o ec_isogeny.o validate.o SIDH.o SIDH_setup.o fpx.o $(EXTRA_OBJECTS)
OBJECTS_TEST=test_extras.o
OBJECTS_KEYGEN=keygen.o $(OBJECTS_TEST) $(OBJECTS)
OBJECTS_SIGNING=signing.o $(OBJECTS_TEST) $(OBJECTS)
OBJECTS_VERIFY=verify.o $(OBJECTS_TEST) $(OBJECTS)
OBJECTS_SIGNATURESCHEME=signature_scheme.o keygen.o signing.o verify.o keccak.o $(OBJECTS_TEST) $(OBJECTS)

lib: $(OBJECTS_SIGNATURESCHEME)
	$(CC) -shared -Wl,-soname,libsisig.so.1 -o libsisig.so.1.0   $(OBJECTS_SIGNATURESCHEME)

signature_scheme: $(OBJECTS_SIGNATURESCHEME)
	$(CC) -lpthread -o signature_scheme $(OBJECTS_SIGNATURESCHEME) $(ARM_SETTING)

keygen: $(OBJECTS_KEYGEN)
	$(CC) -lpthread -o keygen $(OBJECTS_KEYGEN) $(ARM_SETTING)

signing: $(OBJECTS_SIGNING)
	$(CC) -lpthread -o signing $(OBJECTS_SIGNING) $(ARM_SETTING)

verifying: $(OBJECTS_VERIFY)
	$(CC) -lpthread -o verify $(OBJECTS_VERIFY) $(ARM_SETTING)

kex.o: kex.c SIDH_internal.h
	$(CC) $(CFLAGS) kex.c

ec_isogeny.o: ec_isogeny.c SIDH_internal.h
	$(CC) $(CFLAGS) ec_isogeny.c

validate.o: validate.c SIDH_internal.h
	$(CC) $(CFLAGS) validate.c

SIDH.o: SIDH.c SIDH_internal.h
	$(CC) $(CFLAGS) SIDH.c

SIDH_setup.o: SIDH_setup.c SIDH_internal.h
	$(CC) $(CFLAGS) SIDH_setup.c

fpx.o: fpx.c SIDH_internal.h
	$(CC) $(CFLAGS) fpx.c

ifeq "$(GENERIC)" "TRUE"
    fp_generic.o: generic/fp_generic.c
	    $(CC) $(CFLAGS) generic/fp_generic.c
else
ifeq "$(ARCH)" "x64"
    fp_x64.o: AMD64/fp_x64.c
	    $(CC) $(CFLAGS) AMD64/fp_x64.c

    fp_x64_asm.o: AMD64/fp_x64_asm.S
	    $(CC) $(CFLAGS) AMD64/fp_x64_asm.S
endif
endif

test_extras.o: tests/test_extras.c
	$(CC) $(CFLAGS) tests/test_extras.c

keygen.o: keygen.c SISig.h
	$(CC) $(CFLAGS) keygen.c

signing_algorithm.o: signing.c SISig.h
	$(CC) $(CFLAGS) signing.c

verifying_algorithm.o: verify.c SISig.h
	$(CC) $(CFLAGS) verify.c

signature_scheme.o: tests/signature_scheme.c SISig.h
	$(CC) $(CFLAGS) tests/signature_scheme.c

keccak.o: keccak.c
	$(CC) $(CFLAGS) keccak.c

.PHONY: clean

clean:
	rm signature_scheme libsisig.so.1.0 private.key public.key $(OBJECTS_SIGNATURESCHEME)
