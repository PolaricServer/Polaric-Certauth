CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || printf '%s' '-lssl -lcrypto')
CURL_CFLAGS := $(shell pkg-config --cflags libcurl 2>/dev/null)
CURL_LIBS := $(shell pkg-config --libs libcurl 2>/dev/null || printf '%s' '-lcurl')

CPPFLAGS += $(OPENSSL_CFLAGS) $(CURL_CFLAGS)
LDLIBS += $(OPENSSL_LIBS) $(CURL_LIBS)

TARGET = certclient
SOURCES = certclient.c config.c auth.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJECTS)
