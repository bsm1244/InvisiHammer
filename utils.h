#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <iostream>
#include <vector>
#include <map>

int gt(const void * a, const void * b);
uint64_t median(uint64_t* vals, size_t size);
size_t get_pfn(size_t entry);
size_t get_phys_addr2(uint64_t v_addr, int pmap_fd);
int find_flippable(std::vector<size_t>& vec, std::vector<size_t>& flippable_addr);