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

    num_success = 0
    num_temp = 0
    check = 0

    for line in read_file_chunks(file_name, chunk_size):
        
        if check and "Flip" in line:
            num_success += 1
            check = 0

        if "Compare start" in line :
            check = 1
            num_temp += 1

        # if "compare time" not in line : continue
        # print(line)
        
        # if "dummy" not in line : continue
        # print(line.split(' ')[1].split('MB')[0])

        # a, b, c, d, e, f, g, h, i = map(str, line.strip().split(" "))

    print(num_success/num_temp)