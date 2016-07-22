
.c.o:
	gcc -g -c $?

all: trace_route


trace_route: trace_route.o
	gcc -g -o trace_route trace_route.o -lpcap -lm



