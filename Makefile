
CC ?= gcc
SRCDIR = src/
OUTDIR = build/
INCLUDE_DIR = include/
CFLAGS = -I$(INCLUDE_DIR)

_OBJ = check.o delay.o extts.o liblink.o pkt.o ptp_message.o stats.o \
       tc.o te.o timestamping.o tstest.o
OBJ = $(patsubst %,$(OUTDIR)%,$(_OBJ))
BIN = tstest

$(OUTDIR)$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

$(OUTDIR)%.o: $(SRCDIR)%.c | $(OUTDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR):
	mkdir -p $(OUTDIR)

clean:
	rm $(OUTDIR)*.o $(OUTDIR)$(BIN)
	rmdir $(OUTDIR)

test: $(OUTDIR)$(BIN)
	unshare -r -n pytest --tb=no $(t)

pipeline_test: $(OUTDIR)$(BIN)
	pytest --tb=no $(t)

install: $(OUTDIR)$(BIN)
	cp $(OUTDIR)$(BIN) /usr/local/bin/$(BIN)

.PHONY: clean install test pipeline_test

all: $(BIN)

