#!/usr/bin/env python3
import os, time, subprocess, signal
from dotenv import dotenv_values
config = dotenv_values(".env")

os.system("mkdir ./logs")
os.system(f"lcov --directory {config['OPEN5GS_PATH']} --zerocounters")

for i in range(0, 24):
    for j in range(0, 6): # collect data every 10 minutes
        p = subprocess.Popen("./core_fuzzer.py")
        print(f"Hour: {i}, Minute: {j*10}")
        time.sleep(600)
        p.send_signal(signal.SIGINT)
        time.sleep(2)
        os.system(f"cp ./savedFSM.json ./logs/savedFSM{i}_{j}.json")
        os.system(f"lcov --directory {config['OPEN5GS_PATH']} --capture --output-file ./logs/app{i}_{j}.info --rc lcov_branch_coverage=1 --ignore-errors branch,callback,child,corrupt,count,deprecated,empty,excessive,fork,format,gcov,graph,internal,mismatch,missing,negative,package,parallel,parent,range,source,unsupported,unused,usage,utility,version")
        os.system(f"mongoexport --db=CoreFuzzer --collection={config['DB_NAME']} --out=./logs/db{i}_{j}.json")