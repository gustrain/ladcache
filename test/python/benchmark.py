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
import numpy as np
import time
import sys
import os

K = 1024
M = 1024 * 1024
G = 1024 * 1024 * 1024

# Configuration. TODO: allow to be changed by input.
CAPACITY     = 8*G
QUEUE_DEPTH  = 256
MAX_UNSYNCED = 64
N_USERS      = 1

# Get all filepaths under ROOT.
def get_all_filepaths(root: str, extension: str = "*"):
    # Taken from https://stackoverflow.com/a/18394205
    filepaths = [y for x in os.walk(root) for y in glob(os.path.join(x[0], "*.{}".format(extension)))]
    total_size = sum([os.path.getsize(filepath) for filepath in filepaths])

    return filepaths, total_size

# Load a directory, returning (seconds to load, # bytes loaded).
def benchmark_filepaths(ctx: ladcache.UserState, queue_depth: int, paths: str):
    total_size = 0
    in_flight = 0

    start = time.time()
    while paths or in_flight > 0:
        while (paths and in_flight < queue_depth):
            path = paths.pop()
            ctx.submit(path)
            in_flight += 1
        
        # Perhaps sub-optimal? Should only clear out minimal space?
        while True:
            request = ctx.reap(wait=False)
            if (request == None):
                break

            total_size += request.get_size()
            in_flight -= 1
            del request
    
    # Get the stragglers
    while in_flight > 0:
        request = ctx.reap(wait=True)
        total_size += request.get_size()
        in_flight -= 1
        del request
    duration = time.time() - start

    return duration, total_size


def main():
    np.random.seed(42)

    directories = list(sys.argv)
    if len(directories) < 2:
        print("Please provide at least one directory to load from.")
        return
    
    total_size = 0
    path_groups = []
    for directory in directories:
        paths, size = get_all_filepaths(directory)
        total_size += size
        path_groups.append(paths)


    # Create a very large cache to allow everything to be loaded.
    cache = ladcache.Cache(CAPACITY, QUEUE_DEPTH, MAX_UNSYNCED, N_USERS)
    cache.spawn_threads()

    # Benchmark each directory.
    ctx = cache.get_user_state(0)
    print("Benchmarking {} directories ({} bytes)".format(len(path_groups), total_size))
    for paths,  in directories:
        print("Directory {} ({} files)... ".format(directory, len(paths)), end="")
        duration, size = benchmark_filepaths(cache, paths)
        print("{} bytes, {} seconds ({} MB/s)".format(size, duration, (size / M) / duration))
    
    # Cleanup the cache.
    del cache

    print("Benchmark done.")

if __name__ == "__main__":
    main()