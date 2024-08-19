'''
    Last edit: 05.06.2024
    Name: 01_attack_merging.py

    UPDATE: 06.07.2024
    - Added attack info update to ntfy
    
    UPDATE: 18.08.2024
    - Unified DS SCHEMA extraction
'''

from pathlib import Path
import polars as pl
import os
import re
import io
from prerequisites import *

PATH_TO_PROCESS = Path(Path.cwd(), "01_attacks_processing")
PATH_MERGED = Path(Path.cwd(), "02_attacks_merged")

os.makedirs(PATH_TO_PROCESS, exist_ok=True)
os.makedirs(PATH_MERGED, exist_ok=True)

# ----------------------------------------------

DS_SCHEMA = label_casting()

def process_csv(path: Path):
    df = pl.DataFrame()

    with open(path, "r") as file_csv:
        data_string = file_csv.read()

        # replacing the "inf" and "nan" with 0 - one of the initial and easier options of unifying unknown data - found here: https://scikit-learn.org/stable/modules/impute.html
        data_string = data_string.replace("inf", "0").replace("nan", "0")
        data_string = re.sub(r", ", ",", data_string)
        data_string = re.sub(r" ,", ",", data_string)
        data_string = data_string.replace("not a complete handshake", "0")

        data_bytes = io.BytesIO(data_string.encode("utf-8"))

        df = pl.read_csv(data_bytes, schema_overrides=DS_SCHEMA)

    return df

# ----------------------------------------------

list_attacks_to_process = [attack_dir for attack_dir in PATH_TO_PROCESS.iterdir()]

print(list_attacks_to_process)

counter = 0
for attack_dir in list_attacks_to_process:
    if attack_dir.is_dir():
        list_attack_file = [attack_part for attack_part in attack_dir.iterdir()]
        list_attack_dataset = [process_csv(attack_file) for attack_file in list_attack_file]
    else:
        list_attack_dataset = [process_csv(attack_dir)]
    print("DEBUG: processing attack {}".format(attack_dir.stem))
    print("ATTACK dataset list:\n", list_attack_dataset)

    # if there is no file (0) in the folder - continue
    if len(list_attack_dataset) == 0:
        continue
    # if there is only one file - one CSV - just copy the file
    elif len(list_attack_dataset) == 1:
        list_attack_dataset[0].write_csv(Path(PATH_MERGED, "{}.csv".format(attack_dir.stem)))
    # if there are more files in the directory - merge and save merged
    else:
        merged_dataframe = list_attack_dataset[0].clear()
        for attack_dataset in list_attack_dataset:
            merged_dataframe = pl.concat([merged_dataframe, attack_dataset])

        merged_dataframe.write_csv(Path(PATH_MERGED, "{}.csv".format(attack_dir.stem)))

    attack_update("{}/{}: ATTACK {} finished preprocessing!".format(counter+1, len(list_attacks_to_process), attack_dir.stem))
    counter += 1