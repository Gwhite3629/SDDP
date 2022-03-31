CC=gcc
LINK=gcc
TARGET1=sender
TARGET2=receiver
OBJS=sender.o receiver.o interface.o
LIBS=-pthread
CFLAGS=-g -Wall -Wextra

all: ${TARGET1} ${TARGET2}

${TARGET1}: ${OBJS}
	${CC} -o ${TARGET1} ${OBJSMAIN} ${LIBS}

${TARGET2}: ${OBJS}
	${CC} -o ${TARGET2} ${OBJSMAIN} ${LIBS}

.PHONY : clean

clean:
	rm -f ${TARGET1} core*
	rm -f ${TARGET2} core*
	rm -f *.o core*