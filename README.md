# CoreCrisis
This repository provides the artifact for CoreCrisis. 

## Structure

### Corelearner
This folder provides the code for the State Inference Module. Property-driven equivalence checking is implemented in this module. 

### UERANSIM_CoreTesting
This folder contains a modified implementation of UERANSIM, serves as the Message Adapter. This module can generate and mutate test messages used for both state inference and state machine guided testing. During testing, this module also provides grammar-aware message mutation. 

### CoreFuzzer
This folder includes the Guided Testing Module. 

Implemented features:
- Analysis and comparison of responses (core_fuzzer.py)
- Dynamic FSM refinement (core_fuzzer.py)
- Protocol side-channel crash detection (core_fuzzer.py)
- Logical error detection (core_fuzzer.py)
- Key state labeling (objects/oracle.py)

### Other_fuzzers
This folder contains the modified fuzzers for our evaluation, including AFLNet, BooFuzz, and Fuzzowski. 

## Instructions
We provided detailed instructions for bulid and running the artifact in each subfolder. 

A general workflow is that to learn the state machine using Corelearner and put the generated state machine into CoreFuzzer for guided testing. 

We have also provided the learned state machine in the in CoreFuzzer so you can run it directly. 