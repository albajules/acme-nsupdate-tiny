#!/usr/bin/env python
# coding: utf-8
import argparse, base64, binascii, hashlib, json, logging, os, re, subprocess, sys, time
try:
    from urllib.request import Request, urlopen # Python 3
except ImportError:
    from urllib2 import Request, urlopen # Python 2
def _b64(s):
    return base64.urlsafe_b64encode(s).decode("utf-8").replace("=", "")
def _cmd(args, data=None):
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(data)
    if p.returncode != 0:
        raise Exception("Cmd: {}\nRet: {}\nError:\n{}".format(" ".join(args), p.returncode, err.decode("utf-8")))
    return out
def _nsupdate(cmd, key):
    _cmd(["nsupdate"], (("" if key is None else "key " + key + "\n") + cmd + "\nsend").encode("utf-8"))
def _req(url, data=None):
    headers = {"Content-Type": "application/jose+json", "User-Agent": "acme-nsupdate-tiny"}
    resp = urlopen(Request(url, data=None if data is None else data.encode("utf-8"), headers=headers))
    resp_data, code, headers = resp.read().decode("utf-8"), resp.getcode(), resp.info()
    resp.close()
    logging.info("Url: %s\nData:\n%s\nCode: %d\nHeaders:\n%s\nResponse:\n%s", url, data, code, headers, resp_data)
    if code not in [200, 201, 204]:
        raise ValueError("Url: {}\nData:\n{}\nCode: {}\nResponse:\n{}".format(url, data, code, resp_data))
    return None if resp_data == "" else json.loads(resp_data), headers
def _post(url, protected, key, payload=None):
    payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf-8"))
    protected["url"] = url
    protected64 = _b64(json.dumps(protected).encode("utf-8"))
    sig = _cmd(["openssl", "dgst", "-sha256", "-sign", key], (protected64 + "." + payload64).encode("utf-8"))
    resp, headers = _req(url, json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(sig)}))
    protected["nonce"] = headers["Replay-Nonce"]
    return resp, headers.get("Location")
def _poll(url, obj, protected, key, status, err):
    attempts = 0
    while obj["status"] != "valid":
        if attempts >= 30: raise ValueError("Timeout polling for " + err)
        time.sleep(2)
        obj.update(_post(url, protected, key)[0])
        if obj["status"] not in status + ["valid"]:
            raise ValueError("{} is {}".format(err, obj["status"]))
        attempts += 1
def sign(keyfile, csrfile, directory_url, nskey=None, emails=None):
    key = _cmd(["openssl", "rsa", "-in", keyfile, "-noout", "-text"]).decode("utf-8")
    key = re.search(r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", key, re.MULTILINE | re.DOTALL)
    keye = "{0:x}".format(int(key.group(2)))
    keye = _b64(binascii.unhexlify("0" * (len(keye) % 2) + keye))
    keyn = _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", key.group(1))))
    directory = _req(directory_url)[0]
    nonce = _req(directory["newNonce"])[1]["Replay-Nonce"]
    protected = {"alg": "RS256", "nonce": nonce, "jwk": {"kty": "RSA", "e": keye, "n": keyn}}
    jwk = hashlib.sha256(json.dumps(protected["jwk"], sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
    protected["kid"] = _post(directory["newAccount"], protected, keyfile, {"termsOfServiceAgreed": True})[1]
    del protected["jwk"]
    if emails is not None:
        _post(protected["kid"], protected, keyfile, {"contact": ["mailto:" + m for m in emails]})
    csr = _cmd(["openssl", "req", "-in", csrfile, "-noout", "-text"]).decode("utf-8")
    subject = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", csr)
    domains = set([] if subject is None else [subject.group(1)])
    sans = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", csr, re.MULTILINE | re.DOTALL)
    domains.update(set([] if sans is None else [s[4:] for s in sans.group(1).split(", ") if s.startswith("DNS:")]))
    for d in domains:
        if not re.match(r"^[a-zA-Z0-9.*_-]+$", d): raise ValueError("Invalid domain name: " + d)
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, order_url = _post(directory["newOrder"], protected, keyfile, order_payload)
    for authz_url in order["authorizations"]:
        authz = _post(authz_url, protected, keyfile)[0]
        chall = [c for c in authz["challenges"] if c["type"] == "dns-01"][0]
        record = _b64(hashlib.sha256((chall["token"] + "." + _b64(jwk)).encode("utf-8")).digest())
        _nsupdate("add _acme-challenge." + authz["identifier"]["value"] + ". 1 txt \"" + record + "\"", nskey)
        _post(chall["url"], protected, keyfile, {})
        _poll(authz_url, authz, protected, keyfile, ["pending"], "Challenge for " + authz["identifier"]["value"])
        _nsupdate("del _acme-challenge." + authz["identifier"]["value"] + ". txt", nskey)
    csr = _cmd(["openssl", "req", "-in", csrfile, "-outform", "DER"])
    _post(order["finalize"], protected, keyfile, {"csr": _b64(csr)})
    _poll(order_url, order, protected, keyfile, ["pending", "processing"], "Order")
    return order["certificate"]
def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--tsig-key", default=None, help="nsupdate TSIG key or path to key file")
    parser.add_argument("--email", default=None, nargs="*", help="emails (e.g. user@example.com) for your account-key")
    parser.add_argument("--production", default=False, action="store_true", help="use production server")
    parser.add_argument("--verbose", default=False, action="store_true", help="show debug info")
    args = parser.parse_args(argv)
    if args.tsig_key and os.path.exists(args.tsig_key):
        with open(args.tsig_key) as f: args.tsig_key = f.read().strip()
    if args.tsig_key and "\n" in args.tsig_key: raise ValueError("TSIG key must not contain newlines")
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    print(sign(args.account_key, args.csr, "https://acme-v02.api.letsencrypt.org/directory" if args.production else "https://acme-staging-v02.api.letsencrypt.org/directory", args.tsig_key, args.email))
if __name__ == "__main__":
    main(sys.argv[1:])
