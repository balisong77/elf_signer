SRC = signer.c
EXEC = signer

all: $(SRC)
	gcc -g -o $(EXEC) $(SRC) -lcrypto
clean: 
	$(RM) $(EXEC)