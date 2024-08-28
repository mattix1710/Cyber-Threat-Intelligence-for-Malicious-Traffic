from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
import polars as pl
from ipaddress import ip_address
from prerequisites import *
import json
import time

DATASETS_USED = ["Recon-OSScan-shuffled"]#["DNS_Spoofing-shuffled"]

DUMP_PATH = Path(Path.cwd(), "04_attack_recognition_trained")
DS_SCHEMA = label_casting("00_type_cast_data/type_list.txt")
DS_PATH = Path(Path.cwd(), "03.2_attacks_shuffled_divided/train")

def cast_ip_to_int64(ip_string: str):
    '''
    converts IP from `string` format to `int64` using *ipaddress* module:
    e.g. IP address of `192.168.1.1` will be represented as `3232235777` number, which is then easily interpreted by ML
    '''
    return int(ip_address(ip_string))

attacks_importances = {}

for ds in DATASETS_USED:
    print("INFO: processing dataset of {}".format(ds))
    # reading custom model from dump
    #attack_trained_pickled = open(Path(DUMP_PATH, "dump_{}.dmp".format(ds)), "rb")
    #forest_class = pickle.load(attack_trained_pickled)
    #attack_trained_pickled.close()

    forest_class = RandomForestClassifier(n_estimators=250, verbose=1, random_state=0, n_jobs=-2)

    # preparing a dataset with the same values as from original model
    att_train = pl.read_csv(Path(DS_PATH, "train_{}.csv".format(ds)), schema_overrides=DS_SCHEMA)
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

    print("INFO: fitting! ({})".format(ds))
    stopwatch = time.time()
    forest_class.fit(X_train, y_train)
    print("INFO: fitting ended in: {}s".format(round(time.time()-stopwatch, 2)))
    
    N_REPEATS = [1, 5, 10]
    
    local_importances = {}
    
    for rep in N_REPEATS:
        print("INFO: evaluating features by permutation of {} repeats! ({})".format(rep, ds))
        started = time.time()
        perms = permutation_importance(forest_class, X_train, y_train, n_repeats=rep, random_state=0, n_jobs=-1)
        print("INFO: processing DONE in {}s!".format(round(time.time()-started,2)))
        
        custom_perms = {}
        for imports in perms:
            custom_perms[imports] = perms[imports].tolist()

        local_importances[rep] = custom_perms
    
    attacks_importances[ds] = local_importances
        
# saving the outputs to the json 
with open("jsoned_perm_features.json", "w") as file_jsoned:
    json.dump(attacks_importances, file_jsoned, indent=4)