from pathlib import Path
import os
import json
from datetime import datetime
import subprocess
import concurrent.futures
import copy

from logger import make_info_log, make_error_log, processing_update

# SET DATA PATHS HERE

SRC_PCAPS_DIR = Path(Path.cwd(), "./pcaps_extracted")
OUT_FLOWS_DIR = Path(Path.cwd(), "./flows")

# INFO: lists need to be at least empty - used mostly for debug purposes and if there is a need to process only a part of files
LIST_ALLOWED = ["DDoS"]
LIST_DISALLOWED = [] # e.g. ["DDoS", "DoS", "Mirai"]

# THREADS_PER_PROCESS * WORKERS < THREADS ON THE SYSTEM
THREADS_PER_PROCESS = 8
WORKERS = 3

# EOF SET DATA

def get_directories(path):
    num_directories = 0
    dir_list = []

    for item in path.iterdir():
        if any(item.stem.find(fragment) == 0 for fragment in LIST_DISALLOWED):
            continue
        if item.is_dir() and (any(fragment in item.stem for fragment in LIST_ALLOWED) or len(LIST_ALLOWED) == 0):
            num_directories += 1
            dir_list.append(item)
    return dir_list, num_directories

dir_list, num_directories = get_directories(SRC_PCAPS_DIR)
process_counter = 0

logger = open("flow_analyzer.log", "w")

configs_template = {
    "pcap_file_address": "",
    "output_file_address": "",
    "label": "Benign",
    "number_of_threads": THREADS_PER_PROCESS,
    "feature_extractor_min_flows": 4000,
    "writer_min_rows": 6000,
    "read_packets_count_value_log_info": 10000,
    "check_flows_ending_min_flows": 20000,
    "capturer_updating_flows_min_value": 5000,
    "max_flow_duration": 120000,
    "activity_timeout": 5000,
    "floating_point_unit": ".4f",
    "max_rows_number": 800000,
    "features_ignore_list": ["active_min", "active_max", "active_mean", "active_std", "active_median", "active_skewness", "active_cov", "active_mode", "active_variance", "idle_min", "idle_max", "idle_mean", "idle_std", "idle_median", "idle_skewness", "idle_cov", "idle_mode", "idle_variance"]
}

def process_pcap(pcap_flow):
    if pcap_flow.is_file():
        return
    # make a directory
    out_dir = Path(OUT_FLOWS_DIR, pcap_flow.stem)
    if not out_dir.is_dir():
        os.makedirs(out_dir)
    
    flow_file_list = [file for file in pcap_flow.iterdir()]

    if len(flow_file_list) == 0:
        return
    
    processing_update(f"Processing of {flow_file_list[0].stem} started at {datetime.now()}")
    log = make_info_log(f"processing {flow_file_list[0].stem}")
    logger.write(f"{datetime.now()} | {log}\n")

    configs = copy.deepcopy(configs_template)

    configs['label'] = str(flow_file_list[0].stem)
    configs['output_file_address'] = str(Path(out_dir, f"{flow_file_list[0].stem}.csv"))

    # regarding of the number of files, it is needed to convert the files to .PCAP hence all recorded traffic was saved in PCAPNG format (even with .PCAP extension)
    subprocess.run(["mergecap.exe", "-w", f"traffic_merged_{flow_file_list[0].stem}.pcap", "-F", "pcap", f"{pcap_flow}/*"])

    configs['pcap_file_address'] = str(Path(Path.cwd(), f"traffic_merged_{flow_file_list[0].stem}.pcap"))

    log = make_info_log(f"creating .csv flow file of {flow_file_list[0].stem}")
    logger.write(f"{datetime.now()} | {log}\n")

    with open(f"temp_config_{flow_file_list[0].stem}.json", "w") as config_file:
        json.dump(configs, config_file, indent=3)
    try:
        flow_processed = subprocess.Popen(f"ntlflowlyzer.exe -c temp_config_{flow_file_list[0].stem}.json", creationflags=subprocess.CREATE_NEW_CONSOLE)
        flow_processed.wait()
    except Exception as e:
        log = make_error_log(e)
        logger.write(f"{datetime.now()} | {log}\n")
        log = make_error_log(flow_processed.stderr)
        logger.write(f"{datetime.now()} | {log}\n")

    log = make_info_log(f"done making .csv flow file of {flow_file_list[0].stem}")
    logger.write(f"{datetime.now()} | {log}\n")
    
    return f"{flow_file_list[0].stem}"

if not OUT_FLOWS_DIR.is_dir():
    log = make_info_log("INFO: creating directory `./flows/`")
    logger.write(f"{datetime.now()} | {log}\n")
    os.makedirs(OUT_FLOWS_DIR)

log = make_info_log(f"INFO: Process list {[item.stem for item in dir_list]}")
logger.write(f"{datetime.now()} | {log}\n")

with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
    futures = {executor.submit(process_pcap, pcap_flow) for pcap_flow in dir_list}
    for future in concurrent.futures.as_completed(futures):
        try:
            processed_name = future.result()

            if processed_name == None:
                continue
            
            process_counter += 1
            
            processing_update(f"{process_counter}/{num_directories}\n\nProcessing of {processed_name} FINISHED at {datetime.now()}")
            
            # cleaning temp files
            curr_path = Path.cwd()
            Path(curr_path, f"traffic_merged_{processed_name}.pcap").unlink()
            Path(curr_path, f"temp_config_{processed_name}.json").unlink()
        except Exception as e:
            log = make_error_log(e)
            logger.write(f"{datetime.now()} | {log}\n")

logger.close()