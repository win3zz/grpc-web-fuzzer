import importlib
import struct
import requests
import os
import subprocess
from google.protobuf import descriptor_pool, json_format, message_factory


class GRPCWebFuzzer:
    def __init__(self, proto_content, message_name):
        self.proto_content = proto_content
        self.message_name = message_name
        self.proto_filename = f"{message_name}.proto"
        self.pb2_filename = f"{message_name}_pb2.py"

        self.pool = descriptor_pool.Default()
        self.factory = message_factory.MessageFactory()

        # Compile only if needed
        self._prepare_proto()
        self._load_descriptors()

    # ----------------------------------------------------------------------

    def _prepare_proto(self):
        """Write and compile proto only if it does not already exist."""
        need_compile = False

        # 1. Write proto if missing
        if not os.path.exists(self.proto_filename):
            print(f"[+] Creating new proto file: {self.proto_filename}")
            with open(self.proto_filename, "w") as f:
                f.write(self.proto_content)
            need_compile = True
        else:
            print(f"[+] Using cached proto: {self.proto_filename}")

        # 2. Compile only if pb2 missing
        if not os.path.exists(self.pb2_filename):
            print(f"[+] Compiling {self.proto_filename} → {self.pb2_filename}")
            need_compile = True

        if need_compile:
            cmd = [
                "python3",
                "-m",
                "grpc_tools.protoc",
                f"-I.",
                f"--python_out=.",
                self.proto_filename,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print("PROTOC ERROR:")
                print(result.stderr)
                raise RuntimeError("Protoc failed")

        # Import generated pb2
        mod_name = self.message_name + "_pb2"
        self.module = importlib.import_module(mod_name)

    # ----------------------------------------------------------------------

    def _load_descriptors(self):
        """Load descriptors and auto-detect package + messages."""
        self.file_desc = self.pool.FindFileByName(self.proto_filename)

        self.package = self.file_desc.package
        self.messages = list(self.file_desc.message_types_by_name.keys())

        print("[+] Package:", self.package)
        print("[+] Messages:", self.messages)

    # ----------------------------------------------------------------------

    def create_message(self, message_name, payload_dict):
        full_name = f"{self.package}.{message_name}"

        desc = self.pool.FindMessageTypeByName(full_name)
        msg_class = desc._concrete_class

        msg = msg_class()
        json_format.ParseDict(payload_dict, msg)

        return msg.SerializeToString()

    # ----------------------------------------------------------------------

    def encode_grpc_web(self, msg_bytes):
        return b"\x00" + struct.pack(">I", len(msg_bytes)) + msg_bytes

    # ----------------------------------------------------------------------

    def call(self, url, message_name, payload_dict,
             proxies=None,
             verify_ssl=False,
             ca_cert_path=None,
             extra_headers=None):

        msg = self.create_message(message_name, payload_dict)
        body = self.encode_grpc_web(msg)

        headers = {
            "Content-Type": "application/grpc-web+proto",
            "X-Grpc-Web": "1",
            "Accept": "application/grpc-web+proto",
            "X-HackerOne-Research": "win3zz",
        }

        if extra_headers:
            headers.update(extra_headers)

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(
            url=url,
            headers=headers,
            data=body,
            proxies=proxies,
            verify=ca_cert_path if verify_ssl else False
        )

        return resp

    # ----------------------------------------------------------------------
    # NEW FEATURE: Iterator
    # ----------------------------------------------------------------------

    def fuzz_iterator(self, url, message_name, text_file_path, proxies=None, ca_cert_path=None):
        """
        Read list of payload values from a text file and fuzz them.
        """

        if not os.path.exists(text_file_path):
            raise FileNotFoundError(f"No such file: {text_file_path}")

        print(f"[+] Fuzzing using values from: {text_file_path}")

        with open(text_file_path, "r") as f:
            for line in f:
                value = line.strip()
                if not value:
                    continue

                payload = {"email":value,"redirectUrl":"https://altius-dsb.andurildev.com/","appendToken":True}
                print(f"[+] Testing email = {value}")

                resp = self.call(
                    url,
                    message_name,
                    payload,
                    proxies=proxies,
                    verify_ssl=False
                )

                print(f"    → Status: {resp.status_code}")
                print(f"    → Raw Response: {resp.content[:80]}\n")


# =====================================================================
#                          USAGE EXAMPLE
# =====================================================================
if __name__ == "__main__":

    # ----------------- Dynamic config -----------------
    TARGET_HOST = "https://altius-dsb.andurildev.com"
    SERVICENAME = "anduril.auth.v2.Idps"
    METHODNAME = "GetSSOURL"
    PACKAGE = "anduril.auth.v2"
    MESSAGE = "GetSSOURLRequest"

    # Dynamic embedded proto
    PROTO_TEMPLATE = """
    syntax = "proto3";

    package {PACKAGE};

    message {MESSAGE} {{
        string email = 1;
        string redirectUrl = 2;
        bool appendToken = 3;
    }}
    """
    
    # Payloads (text file)
    PAYLOADS_FILE = "payloads.txt"
    
    # Proxy (Burp)
    PROXIES = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
    
    # CERT CONFIG
    CA_CERT_PATH = "/home/bipin/Downloads/Burp-Cert"
    
    TARGET_PATH = "/" + SERVICENAME + "/" + METHODNAME
    TARGET_URL = TARGET_HOST + TARGET_PATH
    print(f"[+] Full URL: {TARGET_URL}")

    PROTO_CONTENT = PROTO_TEMPLATE.format(
        PACKAGE=PACKAGE,
        MESSAGE=MESSAGE
    )

    # Init fuzzer
    fuzzer = GRPCWebFuzzer(PROTO_CONTENT, MESSAGE)
    
    # --------- Execute Iterator Fuzzing ----------
    fuzzer.fuzz_iterator(
        TARGET_URL,
        MESSAGE,
        text_file_path=PAYLOADS_FILE,
        proxies=PROXIES,
        ca_cert_path=CA_CERT_PATH
    )
