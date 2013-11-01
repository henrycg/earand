# Compile for x86
CC = gcc
LIBS = -lssl -lcrypto 

# Compile for DD-WRT router
#CC = ~/ddwrt/toolchain-mipsel_gcc4.1.2/bin/mipsel-linux-uclibc-gcc
#LIBS = -ldl libssl.a libcrypto.a 

CFLAGS = -g -Wall -O1 -pedantic -std=gnu99 #-DDEBUG 
LDFLAGS = $(CFLAGS) 
TEST_SCRIPT = ./mkmutest

#####
# Sources 

HEADERS = bn_prime.h dsa_ca.h dsa_device.h dsa_ea.h dsa_params.h\
            gen_keys.h integer_group.h product_proof.h\
            rsa_ca.h rsa_device.h rsa_ea.h rsa_params.h \
            ssl_client.h ssl_server.h util.h
SOURCES = ca_server.c dsa_ca.c dsa_ea.c dsa_device.c \
            dsa_params.c ea_server.c gen_keys.c integer_group.c \
						product_proof.c\
						main.c rsa_ca.c rsa_device.c rsa_ea.c rsa_params.c \
            ssl_client.c ssl_server.c util.c

#####
# Test

TEST_MUTEST = mutest.h
TEST_HEADERS = $(TEST_MUTEST) test_common.h
TEST_SOURCES = mutest.c test_integer_group.c \
	test_product_proof.c\
	test_dsa_device.c\
	test_dsa_params.c\
	test_rsa_device.c\
	test_rsa_params.c\
  test_util.c

TARGET = main 
TARGET_MAIN = main.o

CA_TARGET = ca_server
CA_MAIN = $(CA_TARGET).o

EA_TARGET = ea_server
EA_MAIN = $(EA_TARGET).o

TEST_TARGET = mutest
TEST_MAIN = runmutest.o


MAINS = $(CA_MAIN) $(EA_MAIN) $(TARGET_MAIN) $(TEST_MAIN) 

OBJECTS =  $(SOURCES:.c=.o)
NON_MAIN_OBJECTS = $(filter-out $(MAINS), $(OBJECTS))
TEST_OBJECTS =  $(TEST_SOURCES:.c=.o)
TEST_NON_MAIN_OBJECTS = $(filter-out $(MAINS), $(TEST_OBJECTS))

all: $(TARGET) $(TEST_TARGET) $(CA_TARGET) $(EA_TARGET)

$(OBJECTS): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -c $(INCLUDES)

$(TEST_OBJECTS): $(SOURCES) $(HEADERS) $(TEST_SOURCES) $(TEST_HEADERS)
	$(CC) $(CFLAGS) $(TEST_SOURCES) -c $(INCLUDES)

$(TARGET): $(TARGET_MAIN) $(NON_MAIN_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(TARGET_MAIN) $(NON_MAIN_OBJECTS) $(LIBS)

$(CA_TARGET): $(CA_MAIN) $(NON_MAIN_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(CA_MAIN) $(NON_MAIN_OBJECTS) $(LIBS)

$(EA_TARGET): $(EA_MAIN) $(NON_MAIN_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(EA_MAIN) $(NON_MAIN_OBJECTS) $(LIBS)

$(TEST_TARGET): $(OBJECTS) $(TEST_OBJECTS)
	$(TEST_SCRIPT) $(TEST_MUTEST) $(TEST_NON_MAIN_OBJECTS) | $(CC) -xc -c -o $(TEST_MAIN) -
	$(CC) $(LDFLAGS) -o $@ $(NON_MAIN_OBJECTS) $(TEST_OBJECTS) $(TEST_MAIN) $(LIBS)

prime: prime.c prime.h
	$(CC) $(CFLAGS) -o $@ prime.c util.c -lcrypto -lssl

.PHONY: clean
clean:
	rm -fr $(TARGET) $(CA_MAIN) $(OBJECTS) $(TEST_OBJECTS) \
    $(CA_TARGET) $(EA_TARGET) $(TEST_TARGET)
