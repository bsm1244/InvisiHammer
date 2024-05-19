#include "utils.h"

int gt(const void * a, const void * b) {
   return ( *(int*)a - *(int*)b );
}

uint64_t median(uint64_t* vals, size_t size) {
	qsort(vals, size, sizeof(uint64_t), gt);
	return ((size%2)==0) ? vals[size/2] : (vals[(size_t)size/2]+vals[((size_t)size/2+1)])/2;
}

size_t get_pfn(size_t entry) {
    return ((entry) & 0x7fffffffffffff);
}

size_t get_phys_addr2(uint64_t v_addr, int pmap_fd){
	uint64_t entry;
	uint64_t offset = (v_addr / 4096) * sizeof(entry);
	uint64_t pfn;
	bool to_open = false;

	if (pmap_fd == -1) {
		pmap_fd = open("/proc/self/pagemap", O_RDONLY);
		assert(pmap_fd >= 0);
		to_open = true;
	}
	// int rd = fread(&entry, sizeof(entry), 1 ,fp);
	int bytes_read = pread(pmap_fd, &entry, sizeof(entry), offset);

	assert(bytes_read == 8);
	assert(entry & (1ULL << 63));

	if (to_open) {
		close(pmap_fd);
	}

	pfn = get_pfn(entry);
	assert(pfn != 0);
	return (pfn << 12) | (v_addr & 4095);
}

int find_flippable(std::vector<size_t>& vec, std::vector<size_t>& flippable_addr) {
  std::map<size_t, size_t> valueCount;

  // Count the occurrences of each value
  for (size_t value : vec) {
      valueCount[value]++;
  }

  // Output the counts
	int find = 0;
  for (const auto& pair : valueCount) {
      fprintf(stderr, "Count: %ld, address: 0x%lx\n", pair.second, pair.first);
      if(pair.second >= 10){
				flippable_addr.push_back(((size_t)(pair.first)/4096)*4096);
				find = 1;
			}
  }
	return find;
}