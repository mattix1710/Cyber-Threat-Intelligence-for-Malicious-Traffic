from pathlib import Path
import tarfile, zipfile
import os
from datetime import datetime

from logger import make_debug_log, make_info_log

SRC_ARCHIVES_DIR = Path(Path.cwd(), "./src_archives_downloaded")
EXTRACTED_PCAP_DIR = Path(Path.cwd(), "./pcaps_extracted/")

pcap_logs = open("pcap_extracted.log", "w")

if not EXTRACTED_PCAP_DIR.is_dir():
    log = make_info_log("creating directory `./pcaps_extracted/`")
    pcap_logs.write(f"{datetime.now()} | {log}\n")
    os.makedirs(EXTRACTED_PCAP_DIR)

for archive in SRC_ARCHIVES_DIR.iterdir():
    if archive.is_dir():
        continue
    try:
        archive_file = tarfile.open(archive, "r")
        log = make_info_log(f"Extracting files from {archive.stem}")
        pcap_logs.write(f"{datetime.now()} | {log}\n")        
        archive_file.extractall(EXTRACTED_PCAP_DIR)
        archive_file.close()
        log = make_info_log(f"Deleting archive of {archive.stem}")
        pcap_logs.write(f"{datetime.now()} | {log}\n")
        archive.unlink()
        continue
    except tarfile.ReadError:
        pass

    try:
        archive_file = zipfile.ZipFile(archive, "r")
        log = make_info_log(f"Extracting files from {archive.stem}")
        pcap_logs.write(f"{datetime.now()} | {log}\n")
        archive_file.extractall(EXTRACTED_PCAP_DIR)
        archive_file.close()
        log = make_info_log(f"Deleting archive of {archive.stem}")
        pcap_logs.write(f"{datetime.now()} | {log}\n")
        archive.unlink()
    except zipfile.BadZipFile:
        log = make_info_log(f"File {archive.stem} wasn't properly extracted!")
        pcap_logs.write(f"{datetime.now()} | {log}\n")

pcap_logs.close()