from stix2 import NetworkTraffic, ExtensionDefinition, IPv4Address, Identity, Bundle
from stix2.v21.observables import IPv4Address
import uuid
import hashlib

from pathlib import Path, PurePosixPath

class AttackSignatureSTIXBundle():
    # According to STIX v2.1, all CyberObs have to have UUIDv5!
    STIX_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7"
    EXTENSION_UUID_NETWORK_FLOW = uuid.uuid4()
    EXTENSION_UUID_ML_MODEL = uuid.uuid4()
    __if_identity_created = False
    
    PERSONAL_ID = Identity(
        name = "John Smith",
        identity_class = "individual"
    )
    
    def __init__(self) -> None:
        # INFO: a STIX Meta Object
        pass
        
    def create_identity(self, id_name: str = "John Smith", id_class: str = "individual"):
        self.PERSONAL_ID = Identity(
            name = id_name,
            identity_class = id_class
        )
        self.__if_identity_created = True
        
    def create_custom_network_traffic(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocols: list, features: dict, ml_model_path: Path):
        self.network_traffic_flow_ext_def = self.generate_extension_definition(
            ext_uuid = self.EXTENSION_UUID_NETWORK_FLOW,
            ext_schema = "https://raw.githubusercontent.com/mattix1710/Cyber-Threat-Intelligence-for-Malicious-Traffic/main/STIX_schemas/ext-def/network-traffic-flow-characteristics-ext-def.json",
            ext_name = "network-traffic-flow-characteristics-ext-def",
            ext_description = "This schema extends the Network Traffic SCO with most important features of the flow. These features help recognizing and defining different IoT attack types.",
        )

        self.ml_malicious_traffic_detection_ext_def = self.generate_extension_definition(
            ext_uuid = self.EXTENSION_UUID_ML_MODEL,
            ext_schema = "https://raw.githubusercontent.com/mattix1710/Cyber-Threat-Intelligence-for-Malicious-Traffic/main/STIX_schemas/ext-def/ml-malicious-traffic-detection-ext-def.json",
            ext_name = "ml-malicious-traffic-detection-ext-def",
            ext_description = "Extension for referencing an ML model trained for malicious traffic flow detection.",
        )
        
        self.src_ipv4 = self.generate_ipv4(
            ip_uuid = self.STIX_NAMESPACE,
            ip = src_ip
        )
        
        self.dst_ipv4 = self.generate_ipv4(
            ip_uuid = self.STIX_NAMESPACE,
            ip = dst_ip
        )
        
        self.malicious_network_traffic = self.generate_network_traffic(
            src_port = src_port,
            dst_port = dst_port,
            protocols = protocols,
            flow_features = features,
            ml_model_path = ml_model_path
        )
        
    def generate_extension_definition(self, ext_uuid: uuid, ext_schema: str, ext_name: str, ext_description: str, ext_version: str = "1.0.0"):
        if not self.__if_identity_created:
            raise AssertionError
        return ExtensionDefinition(
            id = "extension-definition--{}".format(ext_uuid),
            created_by_ref = self.PERSONAL_ID,
            schema = ext_schema,
            version = ext_version,
            name = ext_name,
            description = ext_description,
            extension_types=["property-extension"],
            # INFO: "extension_properties" field is used only while utilizing "toplevel-property-extension"
        )
        
    def generate_ipv4(self, ip_uuid, ip):
        return IPv4Address(
            id = "ipv4-addr--{}".format(uuid.uuid5(uuid.UUID(ip_uuid), ip)),
            value = ip,
        )
        
    def generate_network_traffic(self, src_port: int, dst_port: int, protocols: list, flow_features: dict, ml_model_path: Path):
        ml_model_hash = self._extracting_the_hash(ml_model_path)
        
        return NetworkTraffic(
            src_port = src_port,
            dst_port = dst_port,
            protocols = protocols,
            src_ref = self.src_ipv4,
            dst_ref = self.dst_ipv4,
            extensions = {
                "extension-definition--{}".format(self.EXTENSION_UUID_NETWORK_FLOW): flow_features,
                "extension-definition--{}".format(self.EXTENSION_UUID_ML_MODEL): {
                    # INFO: property names MUST only contain a-z, 0-9 and underscore (_)
                    "ml_model_path": str(PurePosixPath(ml_model_path)),
                    "ml_model_sha256_hash": ml_model_hash.hexdigest()
                }
            }
        )
        
    def _extracting_the_hash(self, file_path: Path):
        with open(file_path, "rb") as file:
            buffered_f = file.read()
            return hashlib.sha256(buffered_f)

    def get_bundle(self):
        return Bundle(objects = [
            self.network_traffic_flow_ext_def,
            self.ml_malicious_traffic_detection_ext_def,
            self.src_ipv4,
            self.dst_ipv4,
            self.PERSONAL_ID,
            self.malicious_network_traffic
        ])
        
    def display_bundle(self):
        print(Bundle(objects = [
            self.network_traffic_flow_ext_def,
            self.ml_malicious_traffic_detection_ext_def,
            self.src_ipv4,
            self.dst_ipv4,
            self.PERSONAL_ID,
            self.malicious_network_traffic
        ]))