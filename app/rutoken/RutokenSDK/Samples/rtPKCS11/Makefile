ifeq ($(DEBUG),y)
	DEBFLAGS = -O0 -g -ggdb -DDEBUG
else
	DEBFLAGS = -O2 -DNDEBUG
endif

ARCH_CFLAGS_LINUX32 = -march=i486 -mtune=i486
ARCH_CFLAGS_LINUX64 = -march=nocona -mtune=generic
ARCH_CFLAGS_MAC = -Wno-deprecated-declarations -Wno-format-extra-args -arch i386 -arch x86_64
ARCH_CFLAGS_BSD32 = -march=i486 -mtune=i486
ARCH_CFLAGS_BSD64 = -march=nocona -mtune=generic

TARGET = CreateGOST28147-89 CreateGOST34.10-2001 CreateRSA
TARGET += DeleteGOST28147-89 DeleteGOST34.10-2001 DeleteRSA 
TARGET += DeriveWrapUnwrap EncDecRSA EncDecGOST ExtendedFunctions 
TARGET += Info InitToken SignVerifyGOST SignVerifyRSA WaitForSlotEvent

ifeq ($(CROSS),Linux_x86_64)
	ARCH_CFLAGS = ${ARCH_CFLAGS_LINUX64}
else
ifeq ($(CROSS),Linux_x86)
	ARCH_CFLAGS = -m32 ${ARCH_CFLAGS_LINUX32}
else
ifeq ($(shell uname -s),Linux)
ifeq ($(shell uname -n),debian-armel)
	ARCH_CFLAGS = ${ARCH_CFLAGS_DEBIAN_ARMEL}
else
ifeq ($(shell uname -m),x86_64)
	ARCH_CFLAGS = ${ARCH_CFLAGS_LINUX64}
else
	ARCH_CFLAGS = ${ARCH_CFLAGS_LINUX32}
endif
endif
else
ifeq ($(shell uname -s),Darwin)
	ARCH_CFLAGS = ${ARCH_CFLAGS_MAC}
else
ifeq ($(shell uname -s),FreeBSD)
ifeq ($(shell uname -m),amd64)
	ARCH_CFLAGS = ${ARCH_CFLAGS_BSD64}
else
	ARCH_CFLAGS = ${ARCH_CFLAGS_BSD32}
endif
else
	# Unknown
endif
endif
endif
endif
endif

CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable # --pedantic
CFLAGS += -I. -I./Include
CFLAGS += -D_GNU_SOURCE
CFLAGS += $(DEBFLAGS)
CFLAGS += -fPIC -fpic -fno-strict-aliasing -fno-stack-protector -fvisibility=hidden
CFLAGS += $(ARCH_CFLAGS)

ifeq ($(shell uname -s),FreeBSD)
LDFLAGS += -lpthread
else
LDFLAGS += -ldl -lpthread
endif

CLEANFILES = ${TARGET}

dirs = $(shell ls)

.PHONY: ${TARGET}

all:	${TARGET}
	
#${TARGET}:
#	${CC} ${CFLAGS} -o $@ ${SOURCES} ${LDFLAGS}

CreateGOST28147-89:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Create_GOST28147-89/*.c ${LDFLAGS}
CreateGOST34.10-2001:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Create_GOST34.10-2001/*.c ${LDFLAGS}
CreateRSA:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Create_RSA/*.c ${LDFLAGS}
DeleteGOST28147-89:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Delete_GOST28147-89/*.c ${LDFLAGS}
DeleteGOST34.10-2001 :
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Delete_GOST34.10-2001/*.c ${LDFLAGS}
DeleteRSA:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Delete_RSA/*.c ${LDFLAGS}
DeriveWrapUnwrap:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./DeriveWrapUnwrap/*.c ${LDFLAGS}
EncDecGOST:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./EncDec_GOST/*.c ${LDFLAGS}
EncDecRSA:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./EncDec_RSA/*.c ${LDFLAGS}
ExtendedFunctions:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./ExtendedFunctions/*.c ${LDFLAGS}
Info:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./Info/*.c ${LDFLAGS}
InitToken:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./InitToken/*.c ${LDFLAGS}
SignVerifyGOST:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./SignVerify_GOST/*.c ${LDFLAGS}
SignVerifyRSA:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./SignVerify_RSA/*.c ${LDFLAGS}
WaitForSlotEvent:
	@mkdir -p ./Out
	${CC} ${CFLAGS} -o Out/$@  ./WaitForSlotEvent/*.c ${LDFLAGS}


clean:
	rm -r Out
