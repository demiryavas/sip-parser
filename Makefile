# ------------------------------------------------
# Generic Makefile
#
# Author: yanick.rochon@gmail.com
# Date  : 2011-08-10
#
# Changelog :
#   2010-11-05 - first version
#   2011-08-10 - added structure : sources, objects, binaries
#                thanks to http://stackoverflow.com/users/128940/beta
# ------------------------------------------------

# project name (generate executable with this name)
TARGET   = test_sipparser

CC       = gcc
# compiling flags here
# get from environment settings
CPPFLAGS = $(CPPFLAGS_ENV) -DNDEBUG 

CFLAGS   = $(CPPFLAGS) -Wall -g
$(info CFLAGS is $(CFLAGS))

LINKER   = g++ -o
LFLAGS   = -Wall -lm 

# change these to set the proper directories where each files shoould be
SRCDIR   = .
OBJDIR   = .
BINDIR   = .

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
rm       = rm -f
MKDIR_P = mkdir -p

# create obj directory if does not exist
#${OBJDIR}:
#	${MKDIR_P} ${OBJDIR}

$(info $(SOURCES))

$(BINDIR)/$(TARGET): $(OBJECTS)
	@$(LINKER) $@ $(LFLAGS) $(OBJECTS)
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@echo "Cleanup complete!"

.PHONEY: remove
remove: clean
	@$(rm) $(BINDIR)/$(TARGET)
	@echo "Executable removed!"

