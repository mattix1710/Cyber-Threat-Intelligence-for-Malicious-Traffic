import polars as pl
from pathlib import Path

import numpy as np
import json
import os
import time
import pickle
from ipaddress import ip_address

from prerequisites import *
from STIX_SCO_NetworkTraffic_Extended import AttackSignatureSTIXBundle

INPUT_PATH = Path(Path.cwd(), "03.2_attacks_shuffled_divided")
TEST_PATH = Path(INPUT_PATH, "test")
ATTACK_DUMPS_PATH = Path(Path.cwd(), "04_attack_recognition_trained")

STIX_BUNDLES_PATH = Path(Path.cwd(), "FINAL_STIX_Bundles")

os.makedirs(STIX_BUNDLES_PATH, exist_ok=True)

DS_SCHEMA = label_casting("00_type_cast_data/type_list.txt")
COLUMN_LIST = column_list_reader("00_type_cast_data/column_list.txt")

def cast_ip_to_int64(ip_string: str):
    '''
    converts IP from `string` format to `int64` using *ipaddress* module:
    e.g. IP address of `192.168.1.1` will be represented as `3232235777` number, which is then easily interpreted by ML
    '''
    return int(ip_address(ip_string))

def cast_ip_from_int64_to_str(ip_int64):
    '''
    converts IP from `int64` format to `string` using *ipaddress* module:
    e.g. IP address of `3232235777` will be represented as `192.168.1.1` string
    '''
    return str(ip_address(ip_int64))

attack_names = []
TEST_NAME_CUT_POS = 5

for el in TEST_PATH.iterdir():
    attack_names.append(el.stem[TEST_NAME_CUT_POS:])
ATTACK_LIST_SIZE = len(attack_names)

print(attack_names)

# PREDICTIONs AND SIGNATURE EXTRACTION

for att_path in attack_names:
    ATT_TEST_PATH = Path(TEST_PATH, "test_{}.csv".format(att_path))
    
    if not ATT_TEST_PATH.is_file():
        print("ERROR: TEST file is not available!")
        continue
    
    att_test = pl.read_csv(ATT_TEST_PATH, schema_overrides=DS_SCHEMA)
    # extract the protocols list for later signature creation purposes
    protocols_list = att_test.get_column("protocol")    
    # drop unnecessary features (with String type)
    try:
        
        att_test = att_test.drop(["flow_id", "timestamp", "protocol"])
    except:
        print("ERROR: Some column names TO DROP doesn't exist in the dataset!")
    
    try:
        att_test = att_test.with_columns([
            pl.col("src_ip", "dst_ip").map_elements(cast_ip_to_int64, return_dtype=pl.Int64)
        ])
    except pl.exceptions.ColumnNotFoundError:
        print("ERROR: chosen columns were not found! No changes to the dataframe has been made!")  
        
    # extracting attack as 1 and the rest of attacks as "benign"
    # of TEST part
    attack_or_not = []
    for attrib in att_test.get_column("label"):
        if attrib == "BenignTraffic":
            attack_or_not.append(1)
        else:
            attack_or_not.append(0)
    
    df_test = att_test.clone()
    df_test = df_test.with_columns((pl.lit(pl.Series(attack_or_not)).alias('label')))
    y_test = df_test.select('label').to_series().to_list()
    df_test = df_test.drop('label')
    X_test = df_test.to_numpy()
    
    attack_trained_pickled = open(Path(ATTACK_DUMPS_PATH, "dump_{}.dmp".format(att_path)), "rb")
    forest_classifier = pickle.load(attack_trained_pickled)
    attack_trained_pickled.close()
    
    # creating a dataframe of importances
    importances = forest_classifier.feature_importances_
    # print(importances)
    feat_list = []
    for col, imports in zip(COLUMN_LIST, importances):
        feat_list.append((col, imports))
    dtypes = [("feature", "U50"), ("importance", np.float64)]
    arr = np.array(feat_list, dtype=dtypes)
    # sorting an array with descending order 
    arr[::-1].sort(order="importance",)
    # extracting 30 most important features
    arr_top_feats = arr[:30]
    
    print("INFO: predicting!")
    stopwatch = time.time()
    predict_classifier = forest_classifier.predict(X_test)
    print("INFO: predicting ended in: {}s".format(round(time.time()-stopwatch, 2)))
    
    # extract attack name for the use in the dataset
    att_name = att_path[:att_path.find("-shuffled")]
    # add extracted column with appropriate protocol values
    att_test = att_test.with_columns(pl.lit(protocols_list).alias("protocol"))
    # extract predictions to dicts (each prediction = one flow)
    predicted = att_test.filter(predict_classifier == att_name).to_dicts()
    
    bundle_of_flows = []
    # for each prediction
    for el_predict in predicted:
        # create a dictionary of most important features
        predicted_dict = {}
        # from the list of top X important features
        for import_feature in arr_top_feats["feature"]:
            predicted_dict[str(import_feature)] = el_predict[import_feature]
        print(predicted_dict)
        # create STIX SCO Object (custom NetworkTraffic Extended)
        curr_bundle = AttackSignatureSTIXBundle()
        curr_bundle.create_identity(id_name = "Mateusz Szuda")
        curr_bundle.create_custom_network_traffic(
            src_ip = cast_ip_from_int64_to_str(el_predict["src_ip"]),
            dst_ip = cast_ip_from_int64_to_str(el_predict["dst_ip"]),
            src_port = el_predict["src_port"],
            dst_port = el_predict["dst_port"],
            protocols = [el_predict["protocol"]],
            features = predicted_dict,
            ml_model_path = Path(ATTACK_DUMPS_PATH, "dump_{}.dmp".format(att_path))
        )
        print(curr_bundle.get_bundle().serialize())
        bundle_of_flows.append(json.loads(curr_bundle.get_bundle().serialize()))
    # save the objects to JSON
    with open(Path(STIX_BUNDLES_PATH, "SCO_{}.json".format(att_name)), "w") as file_bundles:
        json.dump(bundle_of_flows, file_bundles, indent=4)