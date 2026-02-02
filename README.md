# Simplest gRPC-Web Parameter Fuzzer 

This tool is designed to help **security testers** fuzz **gRPC-Web endpoints** even if they have limited experience with protobufs or gRPC internals. Basic Python knowledge is required.

### Setup

Install following Python dependencies:

```bash
pip install requests protobuf grpcio grpcio-tools
```

### Usage Instructions

Extract message structure, service and method details from the JavaScript code, for example:

```js
const yn = {
    serviceName: "anduril.auth.v2.Idps"
}
const T_ = {
    methodName: "GetSSOURL",
    service: yn,
    requestType: {
        serializeBinary() {
            return Ke.encode(this).finish()
        }
    },
    responseType: {...}
}
const Ke = {
    $type: "anduril.auth.v2.GetSSOURLRequest",
    encode(e, n=a.Writer.create()) {
        return e.email !== "" && n.uint32(10).string(e.email),
        e.redirectUrl !== "" && n.uint32(18).string(e.redirectUrl),
        e.appendToken === !0 && n.uint32(24).bool(e.appendToken),
        n
    },
    decode(e, n) {...}
}
```

From this JavaScript snippet, extract and replace the values in your Python script as shown below:

```python
TARGET_HOST = "https://altius-dsb.andurildev.com"
SERVICENAME = "anduril.auth.v2.Idps"
METHODNAME = "GetSSOURL"
PACKAGE = "anduril.auth.v2"
MESSAGE = "GetSSOURLRequest"

PROTO_TEMPLATE = """
syntax = "proto3";

package {PACKAGE};

message {MESSAGE} {{
    string email = 1;
    string redirectUrl = 2;
    bool appendToken = 3;
}}
"""
```

### Prepare your payload list

Edit the `payload.txt` file and add any payloads you want to fuzz, such as SQLi, Path traversal, Special characters etc.

### Run the script

```bash
python3 grpc_web_fuzzer.py
```
<img width="1229" height="788" alt="Screenshot 2026-02-02 185026" src="https://github.com/user-attachments/assets/be2e17e4-071f-48f9-8d64-4b7e1fdf8c4d" />

== Output in Burp ==

<img width="995" height="590" alt="Screenshot 2026-02-02 184803" src="https://github.com/user-attachments/assets/47cd1215-2aef-41b4-ae9d-dc23385a6a3a" />

#### Other
- https://github.com/nxenon/grpc-pentest-suite

#### Legal Disclaimer

Designed for security researchers, bug bounty hunters, developers, and authorized testers, this tool must only be used on systems you own or have explicit permission to test; you are solely responsible for your actions.
