# ============================================================
# Automation Resources Makefile
# ============================================================

# ---- Variables from parent Makefile --------------------------
VERSION        ?= 1.0.0

# ---- Compiler ------------------------------------------------
CC             := gcc

# ---- Preprocessor Flags --------------------------------------
CPPFLAGS       :=

# ---- Compiler Flags ------------------------------------------
CFLAGS         := -Wall

ifdef DEBUG
    CFLAGS     += -O0 -g -DDEBUG
else
    CFLAGS     += -O2 -DNDEBUG
endif

# ---- Linker Flags --------------------------------------------
LDFLAGS        :=
LDLIBS         :=

# ---- Targets -------------------------------------------------
TARGETS        := stdio_redirection related_process

# ---- Build Rules ---------------------------------------------
.PHONY: all clean

all: $(TARGETS)

stdio_redirection: stdio_redirection.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

related_process: related_process.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) $(TARGETS)
