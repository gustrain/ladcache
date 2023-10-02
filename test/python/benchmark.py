# MIT License

# Copyright (c) 2023 Gus Waldspurger

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ladcache

from glob import glob
from typing import List
import numpy as np
import time
import sys
import os

K = 1024
M = 1024 * 1024
G = 1024 * 1024 * 1024

# Configuration. TODO: allow to be changed by input.
CAPACITY     = 8*G
QUEUE_DEPTH  = 4
MAX_UNSYNCED = 64
N_USERS      = 1

# Get all filepaths under ROOT.
def get_all_filepaths(root):
    # Taken from https://stackoverflow.com/a/18394205
    filepaths = [y for x in os.walk(root) for y in glob(os.path.join(x[0], "*"))]
    total_size = sum([os.path.getsize(filepath) for filepath in filepaths])

    return filepaths, total_size

# Load a directory, returning (seconds to load, # bytes loaded).
def benchmark_filepaths(ctx: ladcache.UserState, queue_depth: int, paths: List[str]):
    total_size = 0
    in_flight = 0

    start = time.time()
    while paths or in_flight > 0:
        while (paths and in_flight < queue_depth):
            path = paths.pop()
            try:
                ctx.submit(path)
                print("in_flight: {} -> {} (added \"{}\")".format(in_flight, in_flight + 1, path))
                in_flight += 1
            except:
                print("unable to submit; resource unavailable; retrying")
                paths.append(path)
        
        # Perhaps sub-optimal? Should only clear out minimal space?
        while True:
            request = ctx.reap(wait=False)
            if (request == None):
                break

            total_size += len(request.get_data())
            print("in_flight: {} -> {} (cleared \"{}\")".format(in_flight, in_flight - 1, request.get_filepath().decode()))
            in_flight -= 1

            del request
    
    # Get the stragglers
    while in_flight > 0:
        request = ctx.reap(wait=True)
        total_size += len(request.get_data())
        in_flight -= 1
        del request
    duration = time.time() - start

    return duration, total_size

def run_benchmark(ctx: ladcache.UserState, queue_depth: int, directory: str):
    try:
        paths, size = get_all_filepaths(directory)
    except FileNotFoundError:
        print("Directory \"{}\" does not exist.".format(directory))
        return
    
    # Run the benchmark
    print("Benchmarking \"{}\" ({} files, {} MB)... ".format(directory, len(paths), size / M), end="")
    duration, bytes_loaded = benchmark_filepaths(ctx, QUEUE_DEPTH, paths)
    if (bytes_loaded != size):
        print("FAIL; incorrect number of bytes loaded: should be {} B, got {} B.".format(size, bytes_loaded))
    else:
        print("{:.4f} MB in {:.4f} seconds ({:.4f} MB/s)".format(size / M, duration, (size / M) / duration))


def main():
    np.random.seed(42)

    # Create a very large cache to allow everything to be loaded.
    cache = ladcache.Cache(CAPACITY, QUEUE_DEPTH, MAX_UNSYNCED, N_USERS)
    cache.spawn_process()
    ctx = cache.get_user_state(0)

    while True:
        directory = input("directory to load: ")
        if directory in {"q", "quit"}:
            break

        run_benchmark(ctx, QUEUE_DEPTH, directory)

    # Cleanup the cache.
    del cache

    print("Benchmark done.")

if __name__ == "__main__":
    main()