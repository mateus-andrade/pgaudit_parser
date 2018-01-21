
BINFOLDER = bin/
INCFOLDER = inc/
SRCFOLDER = src/
OBJFOLDER = obj/

CC = gcc
CFLAGS = -W -Wall -O2 -pedantic
SRCFILES = $(wildcard $(SRCFOLDER)*.c)

all: $(SRCFILES:$(SRCFOLDER)%.c=$(OBJFOLDER)%.o)
	$(CC) $(CFLAGS) $(OBJFOLDER)*.o -o $(BINFOLDER)pgaudit_parser

$(OBJFOLDER)%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o  $@ -I./$(INCFOLDER)

clean:
	@echo Clean...
	@rm -rf $(OBJFOLDER)*
	@rm -rf $(BINFOLDER)*
