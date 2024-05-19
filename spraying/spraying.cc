#include <iostream>
#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <vector>
#include <cstring>

volatile char *start_address = (volatile char *) 0x10000000000;

void create_file(std::string filename){

	std::string filePath = filename;

  std::ofstream writeFile;
	writeFile.open(filePath, std::ios_base::app);
	
  if(writeFile.is_open()){
		for(size_t i = 0; i < 256*1024; i++){
			writeFile << "2";
			for(size_t j = 1; j < 4*1024; j++){
				writeFile << "9";
			}	
		}
    writeFile.close();
  }
}

size_t get_pfn(size_t entry) {
    return ((entry) & 0x7fffffffffffff);
}

size_t get_phys_addr2(uint64_t v_addr, int pmap_fd)
{
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

int main(int argc, char** argv){

	int fd;

	int pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	assert(pmap_fd >= 0);
	
	// Create shared file
	create_file("/dev/shm/feed");
	fprintf(stderr, "create_file finished\n");
	return 0;

	// Failed to open file
	if((fd = open("/dev/shm/feed", O_RDWR)) < 0){
		perror("File Open Error");
		exit(1);
	}

	int shift = stoi(std::string(argv[1]));

	int num_pages = (1<<shift);
	std::vector<size_t> addresses;
	int wait;
	size_t alloc_size = (1<<30);

	//////////////////////////////   Test   //////////////////////////////
	// auto mapped_target = mmap(NULL, (1<<31) - 4096, PROT_READ | PROT_WRITE,
	// 	MAP_SHARED | MAP_POPULATE, fd, 0);

	// if (mapped_target==MAP_FAILED) {
	// 	perror("mmap");
	// 	exit(EXIT_FAILURE);
	// }

	// for(size_t tmp = 0; tmp < (1<<31) - 4096; tmp += 4096){
	// 	fprintf(stderr, "VA: %lx, PA: %lx\n", (size_t)mapped_target + tmp, get_phys_addr2((size_t)mapped_target + tmp, pmap_fd));
	// }
	//////////////////////////////   Test   //////////////////////////////

	for(int i = 0; i < num_pages; i++){
		auto mapped_target = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, fd, 0); // 2MB per mapping

		if (mapped_target==MAP_FAILED) {
			perror("mmap");
			exit(EXIT_FAILURE);
		}
		addresses.push_back((size_t)mapped_target);
	}

	for(int i = 0; i < 1; i++) { //num_pages; i++){
		for(size_t tmp = 0; tmp < 1024*1024*1024; tmp += 4096){
			if(*((char *) (addresses[i] + tmp)) != '9') std::cout << *((char *) (addresses[i] + tmp)) << std::endl;
		}
		fprintf(stderr, "##########################\n");
		// std::cout << "offset0: " << *((char *) (addresses[i] + (size_t)offset)) << std::endl;
	}

	fprintf(stderr,"Wait for key strike\n");

	std::cin >> wait;

	for(int i = 0; i < num_pages; i++){
		munmap((char*)addresses[i], alloc_size);
	}

	return 0;
}