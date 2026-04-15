#define _HAS_EXCEPTIONS 0
#include <class.h>
#include <stdio.h>

#pragma warning(push)
#pragma warning(disable:5045)


ExpClass::ExpClass(){

}

ExpClass::~ExpClass(){

}

int ExpClass::print_hello(char* name)
{
    printf("hello %s\n",name);
    return 0;
}

int ExpClass::put_i(int i)
{
    printf("push %d\n",i);
    this->m_vis.push_back(i);
    return 0;
}

int ExpClass::put_map_i(int i,int j)
{
    printf("push_map_i %d %d\n",i,j);
    this->m_mis.insert(std::pair<int,int>(i,j));
    return 0;
}

#pragma warning(pop)