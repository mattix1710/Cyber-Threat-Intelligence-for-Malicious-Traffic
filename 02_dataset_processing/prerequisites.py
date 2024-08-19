import requests
import re
import polars as pl

def attack_update(log: str):
    try:
        requests.post("REDACTED", data=log)
    except:
        print("ERROR: No connection to external host!")

def attack_current_state(att_name: str, benign_percent: float, attack_percent: float):
    log = f"ATTACK {att_name} status:\nBENIGN - {int(benign_percent*100)}%\nATTACK - {int(attack_percent*100)}%"
    requests.post("REDACTED", data=log)

def label_casting(path = "00_type_cast_data/type_list.txt"):
    type_dict = {}
    with open(path, "r") as file_types:
        file_lines = file_types.readlines()

        for line in file_lines:
            re_list = re.findall(r"^(\w*)\s([\w ]*)$", line)

            if re_list[0][0].find("Int64") != -1:
                type_dict[re_list[0][1]] = pl.Int64
            elif re_list[0][0].find("Float64") != -1:
                type_dict[re_list[0][1]] = pl.Float64
            else:
                type_dict[re_list[0][1]] = pl.String
    
    return type_dict

def column_list_reader(path = "00_type_cast_data/column_list.txt"):
    COLUMN_LIST = []
    with open(path, "r") as f:
        COLUMN_LIST = f.read().splitlines()
    return COLUMN_LIST