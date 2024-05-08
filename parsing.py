import os, sys

def read_file_chunks(file_path, chunk_size=2):
    with open(file_path, 'r') as log_file:
        while True:
            lines = log_file.readlines(chunk_size)
            if not lines:
                break
            for line in lines:
                yield line

if __name__ == '__main__':
    chunk_size = 20000000
    file_name = sys.argv[1]

    for line in read_file_chunks(file_name, chunk_size):
        
        # if "num_acts_per_tREFI:" in line: print("#######################")
        # if "incre" in line: print("#######################")
        if "size" not in line : continue
        a, b, c, d, e, f, g, h, i = map(str, line.strip().split(" "))
        print(e.split(',')[0], i.split("\033[0m")[0])