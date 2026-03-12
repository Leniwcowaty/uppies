import os, ssl, yaml, hashlib, sys
import requests as r
from datetime import datetime as dt
from time import sleep
import urllib3
import sqlite3
from cryptography import x509

urllib3.disable_warnings()

def read_config():
    with open("/uppies/uppies-config/config.yaml", 'r') as file:
        config = yaml.safe_load(file)
    return config

def ntfy_init(config):
    try:
        with open('/uppies/uppies-data/ntfy.conf', 'r') as file:
            endpoint = file.read()
    except FileNotFoundError:
        try:
            url = config["alerts"]["ntfy-url"]
        except KeyError:
            url = "https://ntfy.sh"
        try:
            topic = f"{config["alerts"]["ntfy-topic"]}"
        except KeyError:
            topic = hashlib.sha256(f"{str(dt.now().timestamp())}{os.uname()[1]}".encode('utf-8')).hexdigest()[:14]
        endpoint = f"{url}/{topic}"
        with open('/uppies/uppies-data/ntfy.conf', 'w+') as file:
            file.write(endpoint)
            file.flush()
            file.close()
    return endpoint


def ssl_check(hostname, port, cert):
    cert_pem = ssl.get_server_certificate((hostname, port))
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    expiryDate = cert.not_valid_after_utc
    expiry = int(expiryDate.timestamp())
    return expiry


def host_check(hostname, https, port, path, cert):
    if https:
        try:
            response = r.get(f"https://{hostname}:{port}/{path}", verify=not(cert)).status_code
            https = True
            expiry = ssl_check(hostname, port, cert)
        except r.exceptions.SSLError:
            try:
                response = r.get(f"http://{hostname}:80/{path}").status_code
                https = False
            except r.exceptions.ConnectionError:
                response = 0
                https = False
            expiry = 0
        except r.exceptions.ConnectionError:
            response = 0
            https = False
            expiry = 0

    else:
        try:
            response = r.get(f"http://{hostname}:{port}/{path}").status_code
            https = False
        except r.exceptions.ConnectionError:
            response = 0
            https = False
        expiry = 0

    if response == 200:
        status = True
    else:
        status = False
    result = {"response": response, "status": status, "https": https, "expiry": expiry}
    return result

def main():
    toWrite = []
    conMain = sqlite3.connect("/uppies/uppies-data/uppies.db")
    curMain = conMain.cursor()
    print(f"---------{dt.now()}---------\n", flush=True)

    conf = read_config()
    try:
        alerting = conf["alerts"]["enable"]
    except KeyError:
        sys.exit("Alerting not configured in config file")

    if alerting:
            ntfyEndpoint = os.getenv("NTFY_ENDPOINT")
            ntfyToken = os.getenv("NTFY_TOKEN")
            if ntfyToken != None:
                apiHeader = {"Authorization": ntfyToken}
            else:
                apiHeader = {}
            if ntfyEndpoint == None:
                ntfyEndpoint = ntfy_init(conf)
                os.environ["NTFY_ENDPOINT"] = ntfyEndpoint
            if ntfyToken == None and "ntfy-auth-token" in conf["alerts"]:
                ntfyToken = conf["alerts"]["ntfy-auth-token"]
                os.environ["NTFY_TOKEN"] = ntfyToken

    for key in conf["services"].keys():
        section = conf["services"][key]
        try:
            testedHost = section["hostname"]
        except KeyError:
            sys.exit(f"Hostname not provided in config file")
        try:
            testedHostHttps = section["https"]
        except KeyError:
            sys.exit(f"HTTPS flag not provided in config file")
        if "port" in section:
            testedHostPort = section["port"]
        else:
            if testedHostHttps:
                testedHostPort = 443
            else:
                testedHostPort = 80
        if "path" in section:
            testedHostPath = section["path"]
        else:
            testedHostPath = "/"
        if "self-signed" in section:
            testedHostCert = section["self-signed"]
        else:
            testedHostCert = False

        result = host_check(testedHost, testedHostHttps, testedHostPort, testedHostPath, testedHostCert)
        print(f"Result for {testedHost}: {result}", flush=True)
        toWrite.append((key, result["response"], result["status"], result["https"], result["expiry"], int(dt.now().timestamp())))
    
        if alerting:
            if "status" in conf["alerts"]["events"] and not result["status"]:
                r.post(ntfyEndpoint, headers=apiHeader, data=f"Site {key} status: {result["status"]}, response code: {result["response"]}")

            if "tls" in conf["alerts"]["events"] and testedHostHttps and not result["https"]:
                r.post(ntfyEndpoint, headers=apiHeader, data=f"Site {key} TLS state: {result["https"]}")

            if "deadline" in conf["alerts"]["events"]["expiry"] and testedHostHttps:
                try:
                    expireIn = int((result["expiry"] - int(dt.now().timestamp()))/86400)
                    print(f"Expire in {expireIn}, deadline: {int(conf["alerts"]["events"]["expiry"]["deadline"])}", flush=True)
                    if  expireIn <= int(conf["alerts"]["events"]["expiry"]["deadline"]):
                        r.post(ntfyEndpoint, headers=apiHeader, data=f"Site {key} SSL certificate expiring on: {dt.fromtimestamp(result["expiry"])}, in {expireIn} days")
                except KeyError:
                    sys.exit("Deadline not configured in config file")
        print("\n\n")

    try:
        curMain.executemany(f"INSERT INTO services VALUES (?, ?, ?, ?, ?, ?)", toWrite)    
        conMain.commit()
    except:
        print("Could not commit to the database!\n", flush=True)
    conMain.close()

if __name__ == "__main__":
    con = sqlite3.connect("/uppies/uppies-data/uppies.db")
    cur = con.cursor()
    if cur.execute("SELECT name FROM sqlite_master WHERE name='services'").fetchone() is None:
        cur.execute("CREATE TABLE services(site, rc, st, tls, exp, ts)")
    con.close()

    while True:
        main()
        sleep(int(os.getenv("UPPIES_INTERVAL")))