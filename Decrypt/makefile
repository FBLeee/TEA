src = $(wildcard ./Source/*.c)    #./Source/abc.c
obj = $(patsubst ./Source/%.c,./obj/%.o,$(src))  #./obj/abc.o


target = $(patsubst ./Source/%.c, ./run/%, $(src)) #


myargs = -Wall -g


myparm =

inc = -I ./inc


ALL:$(target)

$(target):./run/%:./obj/%.o
	gcc $< -o $@  $(myparm) $(inc)

$(obj):./obj/%.o:./Source/%.c
	gcc -c $< -o $@  $(myargs) $(inc)


clean:
	-rm -rf $(obj) $(target)


.PHONY:clean ALL

