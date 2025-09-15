from dotenv import dotenv_values
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional, TextIO

# Active fuzzing iteration counter propagated from the fuzzer.
FUZZ_COUNTER = 0

# Base directory for all generated logs.
LOG_DIRECTORY = Path("./logs")

# Internal tracking of the Open5GS core logging thread.
_CORE_PROCESS: Optional[subprocess.Popen] = None
_CORE_LOG_THREAD: Optional[threading.Thread] = None
_CORE_LOG_STOP: Optional[threading.Event] = None

# Match the Open5GS log prefix, e.g. "[amf]".
_CORE_TAG_PATTERN = re.compile(r"\[(?P<tag>[A-Za-z0-9_.-]+)\]")


def setFuzzCounter(counter: int):
    """Propagate the current fuzzing iteration counter to the helpers."""
    global FUZZ_COUNTER
    FUZZ_COUNTER = counter


def setLogDirectory(directory: Path) -> None:
    """Configure the directory used for all log files."""
    global LOG_DIRECTORY
    LOG_DIRECTORY = Path(directory)
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)


def _log_path(prefix: str, counter: Optional[int] = None) -> str:
    """Return the log path with the fuzz counter embedded."""
    if counter is None:
        counter = FUZZ_COUNTER
    safe_prefix = re.sub(r"[^A-Za-z0-9_.-]", "_", prefix)
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    return str(LOG_DIRECTORY / f"{safe_prefix}_fuzz{counter}.log")
# helper functions for start and kill the components

config = dotenv_values(".env")
# set IMSI offset
IMSI_OFFSET = 0
MAX_IMSI_OFFSET = 98

def setOffset(new_offset:int):
    global IMSI_OFFSET
    IMSI_OFFSET = new_offset

def getOffset():
    global IMSI_OFFSET
    return IMSI_OFFSET

def _consume_core_logs(process: subprocess.Popen, counter: int, stop_event: threading.Event) -> None:
    """Demultiplex Open5GS stdout into per-network-function log files."""
    local_handles: Dict[str, TextIO] = {}
    try:
        if process.stdout is None:
            return
        while not stop_event.is_set():
            line = process.stdout.readline()
            if not line:
                break
            match = _CORE_TAG_PATTERN.search(line)
            tag = match.group("tag") if match else "open5gs"
            tag = re.sub(r"[^A-Za-z0-9_.-]", "_", tag.lower())
            handle = local_handles.get(tag)
            if handle is None:
                handle = open(_log_path(tag, counter), "a", encoding="utf-8")
                local_handles[tag] = handle
            handle.write(line)
            handle.flush()
    finally:
        for handle in local_handles.values():
            try:
                handle.flush()
                handle.close()
            except Exception:
                pass
        if process.stdout:
            try:
                process.stdout.close()
            except Exception:
                pass


def _start_core_logger(process: subprocess.Popen, counter: int) -> None:
    """Spawn the background thread that splits Open5GS logs per NF."""
    global _CORE_LOG_THREAD, _CORE_LOG_STOP
    if _CORE_LOG_THREAD and _CORE_LOG_THREAD.is_alive():
        if _CORE_LOG_STOP:
            _CORE_LOG_STOP.set()
        _CORE_LOG_THREAD.join(timeout=5)
    stop_event = threading.Event()
    _CORE_LOG_STOP = stop_event
    _CORE_LOG_THREAD = threading.Thread(
        target=_consume_core_logs,
        args=(process, counter, stop_event),
        daemon=True,
    )
    _CORE_LOG_THREAD.start()


def startCore():
    global _CORE_PROCESS
    cfg = os.path.join(config["OPEN5GS_PATH"], "build", "configs", "sample.yaml")
    process = subprocess.Popen(
        args=["5gc", "-c", cfg],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
        bufsize=1,
    )
    _CORE_PROCESS = process
    _start_core_logger(process, FUZZ_COUNTER)

def startUE():
    with open(_log_path("ue"), "w") as out:
        cfg = os.path.join(config["UERANSIM_PATH"], "config", "open5gs-ue.yaml")
        imsi = f"imsi-{999700000000001 + IMSI_OFFSET}"
        subprocess.Popen(args=["nr-ue", "-c", cfg, "-i", imsi], stdout=out,
                         stderr=out, start_new_session=True)

def startUE2():
    global IMSI_OFFSET
    IMSI_OFFSET += 1
    with open(_log_path("ue2"), "w") as out:
        cfg = os.path.join(config["UERANSIM_PATH"], "config", "open5gs-ue.yaml")
        imsi = f"imsi-{999700000000001 + IMSI_OFFSET}"
        subprocess.Popen(args=["nr-ue", "-c", cfg, "-i", imsi, "-p", "45679"],
                         stdout=out, stderr=out, start_new_session=True)

def startUE3():
    global IMSI_OFFSET
    IMSI_OFFSET += 1
    with open(_log_path("ue3"), "w") as out:
        cfg = os.path.join(config["UERANSIM_PATH"], "config", "open5gs-ue.yaml")
        imsi = f"imsi-{999700000000001 + IMSI_OFFSET}"
        subprocess.Popen(args=["nr-ue", "-c", cfg, "-i", imsi, "-p", "45680"],
                         stdout=out, stderr=out, start_new_session=True)

def startGNB():
    with open(_log_path("gnb"), "w") as out:
        cfg = os.path.join(config["UERANSIM_PATH"], "config", "open5gs-gnb.yaml")
        subprocess.Popen(args=["nr-gnb", "-c", cfg], stdout=out, stderr=out,
                         start_new_session=True)

def killCore():
    global _CORE_PROCESS, _CORE_LOG_THREAD, _CORE_LOG_STOP
    if _CORE_LOG_STOP:
        _CORE_LOG_STOP.set()
    if _CORE_PROCESS and _CORE_PROCESS.poll() is None:
        try:
            _CORE_PROCESS.terminate()
        except Exception:
            pass
    subprocess.run(["pkill", "-2", "-f", "5gc"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc = subprocess.run(["ps", "-ef"], encoding='utf-8', stdout=subprocess.PIPE)
    for line in proc.stdout.split("\n"):
        if "open5gs" not in line:
            continue
        pid = line.split()[1]
        print(f"Killing pid {pid}")
        subprocess.run(["kill", "-2", pid])
    if _CORE_PROCESS:
        try:
            _CORE_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                _CORE_PROCESS.kill()
            except Exception:
                pass
    if _CORE_LOG_THREAD:
        _CORE_LOG_THREAD.join(timeout=5)
    _CORE_PROCESS = None
    _CORE_LOG_THREAD = None
    _CORE_LOG_STOP = None

def killUE():
    subprocess.run(["pkill", "-2", "-f", "nr-ue"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def killGNB():
    subprocess.run(["pkill", "-2", "-f", "nr-gnb"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sendRRCRelease():
    subprocess.Popen(args=["nr-cli", "UERANSIM-gnb-999-70-1", "--exec", "ue-release 1"])
    time.sleep(0.25)
