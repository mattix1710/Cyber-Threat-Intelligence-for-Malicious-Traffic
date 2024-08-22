import polars as pl
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

import os
from shutil import rmtree
import time
import pickle
from ipaddress import ip_address

from prerequisites import attack_update, label_casting

INPUT_PATH = Path(Path.cwd(), "03.2_attacks_shuffled_divided")
TRAIN_PATH = Path(INPUT_PATH, "train")

ATTACK_DUMPS_PATH = Path(Path.cwd(), "04_attack_recognition_trained")

try:
    os.makedirs(ATTACK_DUMPS_PATH)
except FileExistsError:
    rmtree(ATTACK_DUMPS_PATH)
    os.makedirs(ATTACK_DUMPS_PATH)

DS_SCHEMA = label_casting("00_type_cast_data/type_list.txt")

attack_names = []
TRAIN_NAME_CUT_POS = 6

for el in TRAIN_PATH.iterdir():
    attack_names.append(el.stem[TRAIN_NAME_CUT_POS:])
ATTACK_LIST_SIZE = len(attack_names)

def cast_ip_to_int64(ip_string: str):
    '''
    converts IP from `string` format to `int64` using *ipaddress* module:
    e.g. IP address of `192.168.1.1` will be represented as `3232235777` number, which is then easily interpreted by ML
    '''
    return int(ip_address(ip_string))

if_column_list_copied = False

for att_name in attack_names:
    ATT_TRAIN_PATH = Path(TRAIN_PATH, "train_{}.csv".format(att_name))
    
    if not ATT_TRAIN_PATH.is_file():
        print("ERROR: TRAIN file is not available!")
        continue
    att_train = pl.read_csv(ATT_TRAIN_PATH, schema_overrides=DS_SCHEMA)
    
    # drop unnecessary features (with String type)
    try:
        att_train = att_train.drop(["flow_id", "timestamp", "protocol"])
    except:
        print("ERROR: Some column names TO DROP doesn't exist in the dataset!")
    
    try:
        att_train = att_train.with_columns([
            pl.col("src_ip", "dst_ip").map_elements(cast_ip_to_int64, return_dtype=pl.Int64)
        ])
    except pl.exceptions.ColumnNotFoundError:
        print("ERROR: chosen columns were not found! No changes to the dataframe has been made!")  
        
    # extracting labels for training    
    df_train = att_train.clone()
    y_train = df_train.select('label').to_series().to_list()
    df_train = df_train.drop('label')
    X_train = df_train.to_numpy()
    
    # creating a feature/column list
    if not if_column_list_copied:
        with open("00_type_cast_data/column_list.txt", "w") as col_list_file:
            for col in df_train.columns:
                col_list_file.write("{}\n".format(col))
        if_column_list_copied = True
    
    forest_classifier = RandomForestClassifier(n_estimators=250, verbose=1, random_state=0, n_jobs=-2)
    
    print("INFO: fitting! ({})".format(att_name))
    stopwatch = time.time()
    forest_classifier.fit(X_train, y_train)
    log = "INFO: fitting ended in: {}s".format(round(time.time()-stopwatch, 2))
    print(log)
    attack_update(log)
    
    with open(Path(ATTACK_DUMPS_PATH, "dump_{}.dmp".format(att_name)), "wb") as file:
        pickle.dump(forest_classifier, file)