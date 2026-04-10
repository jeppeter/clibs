
#include <class.h>
#include <stdio.h>

#pragma warning(push)
#pragma warning(disable:5045)


ExpClass::ExpClass(){}

ExpClass::~ExpClass(){}

int ExpClass::print_hello(char* name)
{
    printf("hello %s\n",name);
    return 0;
}

#pragma warning(pop)