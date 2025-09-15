# Installation
To build the docker file, execute the following commands:
Copy ``UERANSIM_CoreTesting`` inside this folder
```shell
cp -r ../UERANSIM_CoreTesting/ .
docker image build -t corefuzzer:sm .
```
Afterwards, you can obtain an interactive shell to a docker environment with 
CoreFuzzer installed by executing:
```shell
docker run --rm -v $(pwd):/corefuzzer --privileged -it corefuzzer:sm bash
```

```shell
mkdir logs
./scripts/init_db.py /corefuzzer_deps/open5gs/
cp .env.example .env
./core_fuzzer.py
```

## Usage

`core_fuzzer.py` now accepts command-line arguments that help control each fuzzing
cycle:

* `--iterations` &mdash; run a fixed number of fuzzing cycles. A value of `0`
  (the default) keeps the fuzzer running indefinitely.
  ```shell
  python core_fuzzer.py --iterations 10
  ```
* `--symbols` &mdash; fuzz only the specified NAS message types. Provide a
  comma-separated list using the exact symbol names.
  ```shell
  python core_fuzzer.py --symbols authenticationResponse,serviceRequest
  ```
* `--seed-file` &mdash; preload seed payloads from a JSON or YAML file before
  fuzzing begins. The file must map each NAS message type to a list of encoded
  payload strings. Every payload is inserted for each discovered FSM state and
  marked as interesting so it can be selected immediately by the scheduler.
  ```json
  {
    "authenticationResponse": ["7E0056..."],
    "serviceRequest": ["2E0100..."]
  }
  ```
  ```shell
  python core_fuzzer.py --seed-file seeds.json
  ```
* `--output-log-dir` &mdash; store all UE, gNodeB, and Open5GS component logs in a
  custom directory instead of the default `./logs`. Each Open5GS network
  function now writes to its own log file (for example `amf_fuzz1.log` or
  `smf_fuzz1.log`).
  ```shell
  python core_fuzzer.py --iterations 5 --output-log-dir /tmp/fuzz-logs
  ```

When any of the above options are used, the iteration counter is prepended to
console output and log filenames (for example `amf_fuzz1.log` or
`ue_fuzz1.log`) for easier correlation with stored database records.

## Batch execution

The helper script `scripts/run_fuzzing_batches.sh` sequentially launches the
fuzzer for each NAS message type and stores the resulting logs in dedicated
subdirectories (for example `logs/batch_YYYYMMDD_HHMMSS/registrationrequest`).

### Running every default scenario

1. Open a shell inside the CoreFuzzer environment and change into the project
   directory:
   ```shell
   cd /corefuzzer/CoreFuzzer
   ```
2. (Optional) Choose how many fuzzing iterations you want per scenario. The
   default is one iteration, but you can override it by exporting
   `FUZZ_ITERATIONS`:
   ```shell
   export FUZZ_ITERATIONS=3
   ```
3. Start the batch script. It automatically sweeps through all default NAS
   message scenarios and places the logs for each run in its own directory:
   ```shell
   ./scripts/run_fuzzing_batches.sh
   ```
4. When the script completes, inspect the timestamped batch directory (for
   example `logs/batch_20240915_153000/`). Each NAS message scenario has its own
   subdirectory containing the UE, gNodeB, and per-network-function Open5GS
   logs for that fuzzing run.

You can pass through additional options that `core_fuzzer.py` understands (for
example `--seed-file seeds.yaml`) after the script name:

```shell
./scripts/run_fuzzing_batches.sh --seed-file seeds.yaml
```

Environment variables control the batch behaviour:

* `FUZZ_ITERATIONS` &mdash; number of fuzzing iterations per run (default: `1`).
* `FUZZ_SYMBOL_GROUPS` &mdash; override the default NAS message groups with a
  semicolon-separated list (for example
  `registrationRequest,authenticationResponse;serviceRequest`).
* `FUZZ_LOG_ROOT` &mdash; base directory where batch log folders are created.

