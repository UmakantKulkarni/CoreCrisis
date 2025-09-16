from dotenv import dotenv_values
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, TextIO

# Active fuzzing iteration counter propagated from the fuzzer.
FUZZ_COUNTER = 0

# Base directory for all generated logs.
LOG_DIRECTORY = Path("./logs")

# Location of the Open5GS configuration template that includes logger placeholders.
_CONFIG_TEMPLATE_PATH = Path(__file__).resolve().parent / "sample.yaml"

# Placeholder token within the template that is replaced with the active log directory.
_CONFIG_LOG_PLACEHOLDER = "__LOG_DIR__"

# Default Open5GS install root inside the container. Used if the environment file is
# missing or does not define OPEN5GS_PATH.
_DEFAULT_OPEN5GS_ROOT = Path("/corefuzzer_deps/open5gs")

# Relative path from the Open5GS root to the sample configuration used by the core.
_OPEN5GS_CONFIG_RELATIVE = Path("build") / "configs" / "sample.yaml"

# Internal tracking of the Open5GS core logging thread.
_CORE_PROCESS: Optional[subprocess.Popen] = None
_CORE_LOG_THREAD: Optional[threading.Thread] = None
_CORE_LOG_STOP: Optional[threading.Event] = None

# Mapping of network function name to the corresponding Open5GS binary.
_NF_BINARIES: Dict[str, str] = {
    "amf": "open5gs-amfd",
    "ausf": "open5gs-ausfd",
    "bsf": "open5gs-bsfd",
    "nrf": "open5gs-nrfd",
    "nssf": "open5gs-nssfd",
    "pcf": "open5gs-pcfd",
    "scp": "open5gs-scpd",
    "smf": "open5gs-smfd",
    "udm": "open5gs-udmd",
    "udr": "open5gs-udrd",
    "upf": "open5gs-upfd",
}

# Relative directory name that stores per-network-function configurations.
_NF_CONFIG_SUBDIR = "nf_configs"

# Track the individual network function processes started by the helper.
_ACTIVE_NF_PROCESSES: Dict[str, subprocess.Popen] = {}

# Match the Open5GS log prefix, e.g. "[amf]".
_CORE_TAG_PATTERN = re.compile(r"\[(?P<tag>[A-Za-z0-9_.-]+)\]")


def _candidate_open5gs_roots() -> List[Path]:
    """Return possible Open5GS installation roots ordered by priority."""
    roots: List[Path] = []
    env_root = None
    try:
        env_root = config.get("OPEN5GS_PATH")  # type: ignore[name-defined]
    except NameError:
        env_root = None

    if env_root:
        roots.append(Path(env_root).expanduser())
    roots.append(_DEFAULT_OPEN5GS_ROOT)

    unique_roots: List[Path] = []
    seen: set[str] = set()
    for root in roots:
        resolved = root.expanduser()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        unique_roots.append(resolved)
    return unique_roots


def _resolve_open5gs_config_path() -> Optional[Path]:
    """Locate the Open5GS sample configuration file inside the container."""
    roots = _candidate_open5gs_roots()
    if not roots:
        return None

    for root in roots:
        candidate = root / _OPEN5GS_CONFIG_RELATIVE
        if candidate.exists():
            return candidate

    # Fall back to the highest priority candidate even if it does not exist yet so
    # callers can create it on demand.
    return roots[0] / _OPEN5GS_CONFIG_RELATIVE


def setFuzzCounter(counter: int):
    """Propagate the current fuzzing iteration counter to the helpers."""
    global FUZZ_COUNTER
    FUZZ_COUNTER = counter


def setLogDirectory(directory: Path) -> None:
    """Configure the directory used for all log files."""
    global LOG_DIRECTORY
    LOG_DIRECTORY = Path(directory).expanduser().resolve()
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    _update_open5gs_logger_config(LOG_DIRECTORY)


def _update_open5gs_logger_config(log_directory: Path) -> None:
    """Render the Open5GS configuration with per-component log file paths."""
    config_path = _resolve_open5gs_config_path()
    if config_path is None:
        print("Warning: unable to locate Open5GS configuration path", file=sys.stderr)
        return

    log_directory = Path(log_directory)
    replacement = str(log_directory)

    template_pairs = [(_CONFIG_TEMPLATE_PATH, config_path)]
    nf_template_root = _CONFIG_TEMPLATE_PATH.parent / _NF_CONFIG_SUBDIR
    nf_target_root = config_path.parent / _NF_CONFIG_SUBDIR
    for nf in _NF_BINARIES:
        template_pairs.append(
            (nf_template_root / f"{nf}.yaml", nf_target_root / f"{nf}.yaml")
        )

    for template_path, target_path in template_pairs:
        try:
            template_text = template_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            try:
                template_text = target_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                print(
                    "Warning: Open5GS configuration template is missing and no existing "
                    f"configuration found at {target_path}",
                    file=sys.stderr,
                )
                continue

        if _CONFIG_LOG_PLACEHOLDER not in template_text:
            print(
                f"Warning: log placeholder {_CONFIG_LOG_PLACEHOLDER} not found in "
                f"template {template_path}",
                file=sys.stderr,
            )
            continue

        rendered = template_text.replace(_CONFIG_LOG_PLACEHOLDER, replacement)

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(
                "Warning: failed to update Open5GS logger configuration at "
                f"{target_path}: {exc}",
                file=sys.stderr,
            )


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
    global _CORE_PROCESS, _ACTIVE_NF_PROCESSES
    _update_open5gs_logger_config(LOG_DIRECTORY)
    cfg_path = _resolve_open5gs_config_path()
    if cfg_path is None:
        raise RuntimeError("Unable to determine Open5GS configuration path")

    config_root = cfg_path.parent
    nf_config_root = config_root / _NF_CONFIG_SUBDIR
    if not nf_config_root.exists():
        raise RuntimeError(
            f"Unable to locate per-network-function configuration directory at {nf_config_root}"
        )

    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    processes: Dict[str, subprocess.Popen] = {}
    try:
        for nf_name, binary in _NF_BINARIES.items():
            nf_config_path = nf_config_root / f"{nf_name}.yaml"
            if not nf_config_path.exists():
                raise RuntimeError(
                    f"Missing configuration file for {nf_name} at {nf_config_path}"
                )
            log_path = (LOG_DIRECTORY / f"{nf_name}.log").resolve()
            process = subprocess.Popen(
                args=[binary, "-c", str(nf_config_path), "-l", str(log_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            processes[nf_name] = process
    except Exception:
        for proc in processes.values():
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in processes.values():
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        raise

    _CORE_PROCESS = None
    _ACTIVE_NF_PROCESSES = processes

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
    global _CORE_PROCESS, _CORE_LOG_THREAD, _CORE_LOG_STOP, _ACTIVE_NF_PROCESSES
    if _CORE_LOG_STOP:
        _CORE_LOG_STOP.set()
    if _CORE_PROCESS and _CORE_PROCESS.poll() is None:
        try:
            _CORE_PROCESS.terminate()
        except Exception:
            pass
    for proc in list(_ACTIVE_NF_PROCESSES.values()):
        if proc.poll() is None:
            try:
                proc.terminate()
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
    for proc in list(_ACTIVE_NF_PROCESSES.values()):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
    if _CORE_LOG_THREAD:
        _CORE_LOG_THREAD.join(timeout=5)
    _CORE_PROCESS = None
    _CORE_LOG_THREAD = None
    _CORE_LOG_STOP = None
    _ACTIVE_NF_PROCESSES = {}

def killUE():
    subprocess.run(["pkill", "-2", "-f", "nr-ue"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def killGNB():
    subprocess.run(["pkill", "-2", "-f", "nr-gnb"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sendRRCRelease():
    subprocess.Popen(args=["nr-cli", "UERANSIM-gnb-999-70-1", "--exec", "ue-release 1"])
    time.sleep(0.25)
