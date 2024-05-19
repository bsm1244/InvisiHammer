#include "DRAMAddr.h"

std::string vendor = "sk";

#define MEM_SIZE GB(24)
#define NOT_FOUND ((void*) -1)

size_t remaps[16] = {0,1,2,3,4,5,6,7,14,15,12,13,10,11,8,9};

size_t remappings(size_t row){
  if(vendor == "s")
    return (row / 16) * 16 + remaps[row % 16];
  else
    return row;
}

pte_t *physmap = NULL;

// modify array size when MEM_SIZE is changed
size_t phys_addr[24] = {0,};
size_t virt_addr[24] = {0,};

// initialize static variable
std::map<size_t, MemConfiguration> DRAMAddr::Configs;

void DRAMAddr::set_base_msb(void *buff) {
  base_msb = (size_t) buff & (~((size_t) (1ULL << 30UL) - 1UL));  // get higher order bits above the super page
}

// TODO we can create a DRAMconfig class to load the right matrix depending on
// the configuration. You could also test it by checking if you can trigger bank conflcits
void DRAMAddr::load_mem_config(mem_config_t cfg) {
  DRAMAddr::initialize_configs();
  MemConfig = Configs[cfg];
}

void DRAMAddr::initialize(uint64_t num_bank_rank_functions, volatile char *start_address) {
  // TODO: This is a shortcut to check if it's a single rank dimm or dual rank in order to load the right memory
  //  configuration. We should get these infos from dmidecode to do it properly, but for now this is easier.
  size_t num_ranks;
  if (num_bank_rank_functions==5) {
    num_ranks = RANKS(2);
  } else if (num_bank_rank_functions==4) {
    num_ranks = RANKS(1);
  } else {
    fprintf(stderr, "Could not initialize DRAMAddr as #ranks seems not to be 1 or 2.\n");
    exit(1);
  }
  DRAMAddr::load_mem_config((CHANS(CHANNEL) | DIMMS(DIMM) | num_ranks | BANKS(NUM_BANKS)));
  DRAMAddr::set_base_msb((void *) start_address);
}

size_t DRAMAddr::get_pfn(size_t entry) {
    return ((entry) & 0x7fffffffffffff);
}

size_t DRAMAddr::get_phys_addr(size_t v_addr) 
{
    size_t entry; 
    size_t offset = (v_addr/4096) * sizeof(entry);
    size_t pfn; 
    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    int bytes_read = pread(fd, &entry, sizeof(entry), offset);
    close(fd);
    assert(bytes_read == 8);
    assert(entry & (1ULL << 63)); // present bit
    pfn = get_pfn(entry);
    assert(pfn != 0);
    return (pfn*4096) | (v_addr & 4095); 
}

size_t DRAMAddr::get_phys_addr2(uint64_t v_addr, int pmap_fd)
{
	uint64_t entry;
	uint64_t offset = (v_addr / 4096) * sizeof(entry);
	uint64_t pfn;
	bool to_open = false;
	// assert(fd >= 0);
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

int DRAMAddr::phys_cmp(const void *p1, const void *p2)
{
	return ((pte_t *) p1)->p_addr - ((pte_t *) p2)->p_addr;
}

void DRAMAddr::set_physmap(char *mem)
{
	int l_size = MEM_SIZE / 4096;
	physmap = (pte_t *) malloc(sizeof(pte_t) * l_size);
	int pmap_fd = open("/proc/self/pagemap", O_RDONLY);
	assert(pmap_fd >= 0);

  for (uint64_t tmp = (uint64_t) mem;
	     tmp < (uint64_t) mem + MEM_SIZE; tmp += GB(1)) {

    phys_addr[tmp / GB(1) - 1024] = get_phys_addr2(tmp, pmap_fd);
    virt_addr[tmp / GB(1) - 1024] = tmp;
    size_t res = 0;
    for (size_t i : MemConfig.DRAM_MTX) {
      res <<= 1ULL;
      res |= (size_t) __builtin_parityll(get_phys_addr2(tmp, pmap_fd) & i);
    }
    size_t row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
    fprintf(stderr, "virt_addr[%ld]: 0x%lx, phys_addr[%ld]: 0x%lx, row: %ld\n",tmp / GB(1) - 1024, tmp, tmp / GB(1) - 1024, get_phys_addr2(tmp, pmap_fd), row);
    // fprintf(stderr, "phys_addr[%ld]: 0x%lx, virt_addr[%ld]: 0x%lx\n", tmp / GB(1) - 1024, tmp, tmp / GB(1) - 1024, get_phys_addr2(tmp, pmap_fd));
	}

	close(pmap_fd);
}

size_t DRAMAddr::virt_2_phys(char *v_addr)
{
	for (uint64_t i = 0; i < MEM_SIZE / 4096; i++) {
		if (physmap[i].v_addr ==
		    (char *)((uint64_t) v_addr & ~((uint64_t) (4096 - 1))))
		{

			return physmap[i].
			    p_addr | ((uint64_t) v_addr &
				      ((uint64_t) 4096 - 1));
		}
	}
	return (size_t) NOT_FOUND;
}

char *DRAMAddr::phys_2_virt(char* pp_addr) const
{

  size_t tmp_phys_addr = 0, tmp_virt_addr = 0;
  for(uint64_t i = 0; i < MEM_SIZE / GB(1); i++){
    if((size_t)pp_addr < phys_addr[i] + GB(1) && phys_addr[i] <= (size_t)pp_addr){
      tmp_phys_addr = (size_t)pp_addr;
      tmp_virt_addr = virt_addr[i] + ((size_t)pp_addr - phys_addr[i]);
    }
  }
  // fprintf(stderr, "translation: 0x%lx to 0x%lx", (size_t)pp_addr, tmp_virt_addr);
  if (tmp_phys_addr == 0){
    // modify modulo value when MEM_SIZE is changed
    return (char *)(virt_addr[(size_t)pp_addr % 12]); 
  }

  return (char *)tmp_virt_addr;
}

DRAMAddr::DRAMAddr() = default;

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c) {
  bank = bk;
  row = r;
  col = c;
}

DRAMAddr::DRAMAddr(void *addr) {
  auto p = get_phys_addr((size_t) addr);

  size_t res = 0;
  for (size_t i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityll(p & i);
  }
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

DRAMAddr::DRAMAddr(size_t addr) {
  size_t p = addr;
  size_t res = 0;
  for (size_t i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityll(p & i);
  }
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

size_t DRAMAddr::linearize() const {
  return (this->bank << MemConfig.BK_SHIFT) | (this->row << MemConfig.ROW_SHIFT) | (this->col << MemConfig.COL_SHIFT);
}

void *DRAMAddr::to_virt() {
  return const_cast<const DRAMAddr *>(this)->to_virt();
}

void *DRAMAddr::to_virt() const {
  size_t res = 0;
  size_t l = this->linearize();
  for (size_t i : MemConfig.ADDR_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityll(l & i);
  }
  
  return (void *) this->phys_2_virt((char *)(res));
}

void *DRAMAddr::to_phys() {
  return const_cast<const DRAMAddr *>(this)->to_phys();
}

void *DRAMAddr::to_phys() const {
  size_t res = 0;
  size_t l = this->linearize();
  for (size_t i : MemConfig.ADDR_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityll(l & i);
  }
  return (void *) res;
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  sprintf(buff, "DRAMAddr(b: %zu, r: %zu, c: %zu) = %p",
      this->bank,
      this->row,
      this->col,
      this->to_virt());
  return std::string(buff);
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%ld,%ld,%ld)",
      this->bank,
      this->row,
      this->col);
  return std::string(buff);
}

DRAMAddr DRAMAddr::add(size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return {bank + bank_increment, remappings(remappings(row) + row_increment), col + column_increment};
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  bank += bank_increment;
  row = remappings(remappings(row) + row_increment);
  col += column_increment;
}

// Define the static DRAM configs
MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;

#ifdef ENABLE_JSON

nlohmann::json DRAMAddr::get_memcfg_json() {
  std::map<size_t, nlohmann::json> memcfg_to_json = {
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
       nlohmann::json{
           {"channels", 1},
           {"dimms", 1},
           {"ranks", 1},
           {"banks", 16}}},
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
       nlohmann::json{
           {"channels", 1},
           {"dimms", 1},
           {"ranks", 2},
           {"banks", 16}}}
  };
  return memcfg_to_json[MemConfig.IDENTIFIER];
}

#endif

void DRAMAddr::initialize_configs() {
  struct MemConfiguration single_rank = {
    // .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
    // .BK_SHIFT = 30,
    // .BK_MASK = (0b0000000000000000000000000000001111),
    // .ROW_SHIFT = 0,
    // .ROW_MASK = (0b0000000000000000011111111111111111),
    // .COL_SHIFT = 17,
    // .COL_MASK = (0b0000000000000000000001111111111111),
    // .DRAM_MTX = {          
    //     0b0000000000000100000000000001000000,
    //     0b0000000000001000100000000000000000,
    //     0b0000000000010001000000000000000000,
    //     0b0000000000100010000000000000000000,
    //     0b0000000000000000000010000000000000,
    //     0b0000000000000000000001000000000000,
    //     0b0000000000000000000000100000000000,
    //     0b0000000000000000000000010000000000,
    //     0b0000000000000000000000001000000000,
    //     0b0000000000000000000000000100000000,
    //     0b0000000000000000000000000010000000,
    //     0b0000000000000000000000000000100000,
    //     0b0000000000000000000000000000010000,
    //     0b0000000000000000000000000000001000,
    //     0b0000000000000000000000000000000100,
    //     0b0000000000000000000000000000000010,
    //     0b0000000000000000000000000000000001,
    //     0b1000000000000000000000000000000000,
    //     0b0100000000000000000000000000000000,
    //     0b0010000000000000000000000000000000,
    //     0b0001000000000000000000000000000000,
    //     0b0000100000000000000000000000000000,
    //     0b0000010000000000000000000000000000,
    //     0b0000001000000000000000000000000000,
    //     0b0000000100000000000000000000000000,
    //     0b0000000010000000000000000000000000,
    //     0b0000000001000000000000000000000000,
    //     0b0000000000100000000000000000000000,
    //     0b0000000000010000000000000000000000,
    //     0b0000000000001000000000000000000000,
    //     0b0000000000000100000000000000000000,
    //     0b0000000000000000010000000000000000,
    //     0b0000000000000000001000000000000000,
    //     0b0000000000000000000100000000000000
    //   },
    // .ADDR_MTX = {          
    //     0b0000000000000000010000000000000000,
    //     0b0000000000000000001000000000000000,
    //     0b0000000000000000000100000000000000,
    //     0b0000000000000000000010000000000000,
    //     0b0000000000000000000001000000000000,
    //     0b0000000000000000000000100000000000,
    //     0b0000000000000000000000010000000000,
    //     0b0000000000000000000000001000000000,
    //     0b0000000000000000000000000100000000,
    //     0b0000000000000000000000000010000000,
    //     0b0000000000000000000000000001000000,
    //     0b0000000000000000000000000000100000,
    //     0b0000000000000000000000000000010000,
    //     0b0000000000000000000000000000001000,
    //     0b0001000000000000000000000001000000,
    //     0b0010000000000000000000000000100000,
    //     0b0100000000000000000000000000010000,
    //     0b0000000000000000000000000000000100,
    //     0b0000000000000000000000000000000010,
    //     0b0000000000000000000000000000000001,
    //     0b0000100000000000000000000000000000,
    //     0b0000010000000000000000000000000000,
    //     0b0000001000000000000000000000000000,
    //     0b0000000100000000000000000000000000,
    //     0b0000000010000000000000000000000000,
    //     0b0000000001000000000000000000000000,
    //     0b0000000000100000000000000000000000,
    //     0b1000000000000000000000000000001000,
    //     0b0000000000010000000000000000000000,
    //     0b0000000000001000000000000000000000,
    //     0b0000000000000100000000000000000000,
    //     0b0000000000000010000000000000000000,
    //     0b0000000000000001000000000000000000,
    //     0b0000000000000000100000000000000000
    //   }
  };
  struct MemConfiguration dual_rank = {
    .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
    .BK_SHIFT = 30,
    .BK_MASK = (0b00000000000000000000000000000011111),
    .ROW_SHIFT = 0,
    .ROW_MASK = (0b00000000000000000011111111111111111),
    .COL_SHIFT = 17,
    .COL_MASK = (0b00000000000000000000001111111111111),
    .DRAM_MTX = {          
        0b00000000000000000000010000000000000,
        0b00000000000001000000000000001000000,
        0b00000000000010001000000000000000000,
        0b00000000000100010000000000000000000,
        0b00000000001000100000000000000000000,
        0b00000000000000000000100000000000000,
        0b00000000000000000000001000000000000,
        0b00000000000000000000000100000000000,
        0b00000000000000000000000010000000000,
        0b00000000000000000000000001000000000,
        0b00000000000000000000000000100000000,
        0b00000000000000000000000000010000000,
        0b00000000000000000000000000000100000,
        0b00000000000000000000000000000010000,
        0b00000000000000000000000000000001000,
        0b00000000000000000000000000000000100,
        0b00000000000000000000000000000000010,
        0b00000000000000000000000000000000001,
        0b10000000000000000000000000000000000,
        0b01000000000000000000000000000000000,
        0b00100000000000000000000000000000000,
        0b00010000000000000000000000000000000,
        0b00001000000000000000000000000000000,
        0b00000100000000000000000000000000000,
        0b00000010000000000000000000000000000,
        0b00000001000000000000000000000000000,
        0b00000000100000000000000000000000000,
        0b00000000010000000000000000000000000,
        0b00000000001000000000000000000000000,
        0b00000000000100000000000000000000000,
        0b00000000000010000000000000000000000,
        0b00000000000001000000000000000000000,
        0b00000000000000000100000000000000000,
        0b00000000000000000010000000000000000,
        0b00000000000000000001000000000000000
      },
    .ADDR_MTX = {          
        0b00000000000000000010000000000000000,
        0b00000000000000000001000000000000000,
        0b00000000000000000000100000000000000,
        0b00000000000000000000010000000000000,
        0b00000000000000000000001000000000000,
        0b00000000000000000000000100000000000,
        0b00000000000000000000000010000000000,
        0b00000000000000000000000001000000000,
        0b00000000000000000000000000100000000,
        0b00000000000000000000000000010000000,
        0b00000000000000000000000000001000000,
        0b00000000000000000000000000000100000,
        0b00000000000000000000000000000010000,
        0b00000000000000000000000000000001000,
        0b00001000000000000000000000001000000,
        0b00010000000000000000000000000100000,
        0b00100000000000000000000000000010000,
        0b00000000000000000000000000000000100,
        0b00000000000000000000000000000000010,
        0b00000000000000000000000000000000001,
        0b00000100000000000000000000000000000,
        0b10000000000000000000000000000000000,
        0b00000010000000000000000000000000000,
        0b00000001000000000000000000000000000,
        0b00000000100000000000000000000000000,
        0b00000000010000000000000000000000000,
        0b00000000001000000000000000000000000,
        0b00000000000100000000000000000000000,
        0b01000000000000000000000000000001000,
        0b00000000000010000000000000000000000,
        0b00000000000001000000000000000000000,
        0b00000000000000100000000000000000000,
        0b00000000000000010000000000000000000,
        0b00000000000000001000000000000000000,
        0b00000000000000000100000000000000000
      }
  };
  DRAMAddr::Configs = {
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)), single_rank},
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)), dual_rank}
  };
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {{"bank", p.bank},
       {"row", p.row},
       {"col", p.col}
  };
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

#endif
