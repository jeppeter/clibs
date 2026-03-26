#include <string>
#include <atomic>
#include <thread>
#include <iostream>

// Global
std::string computation(int);
void print(int,std::string);
 
std::atomic<int> arr[3] = {-1, -1, -1};
std::string data[1000]; //non-atomic data

// Thread A, compute 3 values.
void ThreadA(int v0, int v1, int v2)
{
//  assert(0 <= v0, v1, v2 < 1000);
    std::atomic_thread_fence(std::memory_order_acquire);
    std::cout << "before ThreadA" << std::endl;
    data[v0] = computation(v0);
    data[v1] = computation(v1);
    data[v2] = computation(v2);
    std::cout << "ThreadA after computation v0=" << v0 << std::endl;
    std::cout << "ThreadA after computation v1=" << v1 << std::endl;
    std::cout << "ThreadA after computation v2=" << v2 << std::endl;
    std::atomic_store_explicit(&arr[0], v0, std::memory_order_relaxed);
    std::atomic_store_explicit(&arr[1], v1, std::memory_order_relaxed);
    std::atomic_store_explicit(&arr[2], v2, std::memory_order_relaxed);
    std::cout << "exit ThreadA" << std::endl;
}

void CallThreadA()
{
    ThreadA(3,10,20);
}

std::string computation(int i)
{
    data[i] = "cc " + i;
    return data[i];
}
 
// Thread B, prints between 0 and 3 values already computed.
void ThreadB()
{
    std::cout << "in ThreadB" << std::endl;
    int v0 = std::atomic_load_explicit(&arr[0], std::memory_order_relaxed);
    int v1 = std::atomic_load_explicit(&arr[1], std::memory_order_relaxed);
    int v2 = std::atomic_load_explicit(&arr[2], std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);

    std::cout << "enter ThreadB" << std::endl;
//  v0, v1, v2 might turn out to be -1, some or all of them.
//  Otherwise it is safe to read the non-atomic data because of the fences:
    if (v0 != -1)
        print(v0,data[v0]);
    if (v1 != -1)
        print(v1,data[v1]);
    if (v2 != -1)
        print(v2,data[v2]);

    std::cout << "exit ThreadB" << std::endl;
}

void print(int c , std::string v)
{
    std::cout << "data[" << c <<  "]value " << v << std::endl;
    return;
}

int main()
{
    int i,k;
    std::thread t2(ThreadB);
    std::thread t1(CallThreadA);

    t1.join();
    t2.join();

    std::atomic_thread_fence(std::memory_order_release);
    for(k=0;k<3;k++) {
        i = arr[k];
        std::cout << "[" << i << "] = [" << data[i] << "]" << std::endl;
    }
    return 0;
}