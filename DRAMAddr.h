#include <map>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <cstdlib>
#include <random>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <sstream>

#define CHANS(x) ((x) << (8UL * 3UL))
#define DIMMS(x) ((x) << (8UL * 2UL))
#define RANKS(x) ((x) << (8UL * 1UL))
#define BANKS(x) ((x) << (8UL * 0UL))

#define HAMMER_ROUNDS 40000000
#define NUM_BANKS 16
#define DIMM 1
#define CHANNEL 1
#define THRESH 320

uint64_t static inline MB(uint64_t value) {
  return ((value) << 20ULL);
}

uint64_t static inline GB(uint64_t value) {
  return ((value) << 30ULL);
}

// #define MTX_SIZE (34) // for single rank dimm
#define MTX_SIZE (35) // for dual rank dimm

typedef struct {
	char *v_addr;
	size_t p_addr;
} pte_t;

typedef size_t mem_config_t;

struct MemConfiguration {
  size_t IDENTIFIER;
  size_t BK_SHIFT;
  size_t BK_MASK;
  size_t ROW_SHIFT;
  size_t ROW_MASK;
  size_t COL_SHIFT;
  size_t COL_MASK;
  size_t DRAM_MTX[MTX_SIZE];
  size_t ADDR_MTX[MTX_SIZE];
};

class DRAMAddr {
 private:
  // Class attributes
  static std::map<size_t, MemConfiguration> Configs;
  static MemConfiguration MemConfig;
  static size_t base_msb;

  [[nodiscard]] size_t linearize() const;
  

 public:
  size_t bank{};
  size_t row{};
  size_t col{};

  size_t get_pfn(size_t entry);
  size_t get_phys_addr(size_t v_addr);
  size_t get_phys_addr2(size_t v_addr, int pmap_fd);
  static int phys_cmp(const void *p1, const void *p2);
  void set_physmap(char *mem);
  size_t virt_2_phys(char *v_addr);
  char *phys_2_virt(char *pp_addr) const;
  
  // class methods
  static void set_base_msb(void *buff);

  static void load_mem_config(mem_config_t cfg);

  // instance methods
  DRAMAddr(size_t bk, size_t r, size_t c);

  explicit DRAMAddr(void *addr);
  explicit DRAMAddr(size_t addr);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr();

  void *to_virt();
  void *to_phys();

  [[gnu::unused]] std::string to_string();

  static void initialize(uint64_t num_bank_rank_functions, volatile char *start_address);

  [[nodiscard]] std::string to_string_compact() const;

  [[nodiscard]] void *to_virt() const;
  [[nodiscard]] void *to_phys() const;

  [[nodiscard]] DRAMAddr add(size_t bank_increment, size_t row_increment, size_t column_increment) const;

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);

  static void initialize_configs();
};