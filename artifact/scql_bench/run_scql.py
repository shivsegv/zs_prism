"""Measure SecretFlow-SCQL (release 1.0.0b1) on the paper's workloads.

Deployment follows SCQL's centralized tutorial (examples/scdb-tutorial,
Apache-2.0, copied in deploy/): one SCDB server, two SCQL engines (parties
alice and bob), one MySQL server.  Data are Adult (or its upsampling) split
vertically: alice holds (id, age, sex, hours), bob holds (id, education,
marital, occupation, race, country).  Column Control Lists follow the
tutorial's pattern: each party sees its own columns; the peer sees only join
keys after the join, comparison results, and aggregates.

Wide-area conditions follow SCQL's own method (tc netem): traffic between the
two engines -- and only that traffic -- is delayed by 10 ms in each direction
(20 ms RTT) and limited to 100 Mb/s.

Usage:  python run_scql.py --n 45222   (or --n 1000000)
Requires Docker, and the scdbclient/scqltool binaries built from the same
SCQL release (see README.md).
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import shutil
import statistics
import string
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from zsprism.data import load_adult, reference, scaled, Query  # noqa: E402

IMAGE = "secretflow/scql:1.0.0b1"
NETEM_IMAGE = "nicolaka/netshoot:v0.13"
PROJECT = "scqlbench"
QUERIES = {
    "Q3 range-avg": ("SELECT COUNT(*) AS c, AVG(ta.hours) AS a FROM demo.ta AS ta WHERE ta.age >= 30 AND ta.age <= 45",
                     Query("avg", age=(30, 45))),
    "Q4 conj-avg": ("SELECT COUNT(*) AS c, AVG(ta.hours) AS a FROM demo.ta AS ta INNER JOIN demo.tb AS tb ON ta.id = tb.id "
                    "WHERE ta.age >= 30 AND ta.age <= 45 AND tb.education = 'Bachelors' "
                    "AND tb.occupation = 'Exec-managerial'",
                    Query("avg", age=(30, 45), education="Bachelors", occupation="Exec-managerial")),
    "Q5 conj-sel": ("SELECT COUNT(*) AS c, AVG(ta.hours) AS a FROM demo.ta AS ta INNER JOIN demo.tb AS tb ON ta.id = tb.id "
                    "WHERE ta.age >= 70 AND ta.age <= 75 AND ta.sex = 'Female' AND tb.marital = 'Widowed' "
                    "AND tb.country = 'United-States'",
                    Query("avg", age=(70, 75), sex="Female", marital="Widowed", country="United-States")),
}


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def render(work: Path, subst: dict):
    for tpl in work.rglob("*.template"):
        text = tpl.read_text()
        for k, v in subst.items():
            text = text.replace(k, v)
        tpl.with_suffix("").write_text(text)


def sql_quote(v):
    return "'" + str(v).replace("'", "''") + "'"


def write_data(work: Path, recs):
    initdb = work / "mysql" / "initdb"
    with open(initdb / "alice_init.sql", "w") as fa, open(initdb / "bob_init.sql", "w") as fb:
        fa.write("CREATE DATABASE IF NOT EXISTS alice; USE alice;\n"
                 "CREATE TABLE ta (id varchar(16) NOT NULL PRIMARY KEY, age int NOT NULL, "
                 "sex varchar(16) NOT NULL, hours int NOT NULL) ENGINE=InnoDB;\n")
        fb.write("CREATE DATABASE IF NOT EXISTS bob; USE bob;\n"
                 "CREATE TABLE tb (id varchar(16) NOT NULL PRIMARY KEY, education varchar(32) NOT NULL, "
                 "marital varchar(32) NOT NULL, occupation varchar(32) NOT NULL, race varchar(32) NOT NULL, "
                 "country varchar(48) NOT NULL) ENGINE=InnoDB;\n")
        for off in range(0, len(recs), 2000):
            chunk = recs[off:off + 2000]
            fa.write("INSERT INTO ta VALUES " + ",".join(
                f"({sql_quote(r.pid)},{r.age},{sql_quote(r.sex)},{r.hours})" for r in chunk) + ";\n")
            fb.write("INSERT INTO tb VALUES " + ",".join(
                f"({sql_quote(r.pid)},{sql_quote(r.education)},{sql_quote(r.marital)},"
                f"{sql_quote(r.occupation)},{sql_quote(r.race)},{sql_quote(r.country)})" for r in chunk) + ";\n")


def container(service):
    return sh(["docker", "compose", "-p", PROJECT, "ps", "-q", service], cwd=WORK).strip()


def ip_of(cid):
    return sh(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid]).strip()


def netem(cid, peer_ip, enable):
    """Delay/limit only packets from this engine to the peer engine."""
    script = "tc qdisc del dev eth0 root 2>/dev/null || true"
    if enable:
        script += (" && tc qdisc add dev eth0 root handle 1: prio"
                   " && tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 10ms rate 100mbit limit 100000"
                   f" && tc filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip dst {peer_ip}/32 flowid 1:3")
    sh(["docker", "run", "--rm", "--net", f"container:{cid}", "--cap-add", "NET_ADMIN", NETEM_IMAGE, "sh", "-c", script])


def rtt_ms(cid, peer_ip):
    out = sh(["docker", "run", "--rm", "--net", f"container:{cid}", NETEM_IMAGE, "ping", "-c", "5", "-i", "0.2", peer_ip])
    return float(re.search(r"= [\d.]+/([\d.]+)/", out).group(1))


def scdb(user, pw, script: str):
    f = WORK / f".{user}.scql"
    f.write_text(script)
    out = sh([str(SCDBCLIENT), "source", "--host=http://localhost:8080", f"--userName={user}", f"--passwd={pw}",
              f"--usersConfFileName={WORK / 'client' / 'users.json'}", f"--sourceFile={f}", "--sync"])
    if "err:" in out:                      # scdbclient exits 0 even when a statement fails
        raise RuntimeError(f"SCQL statement failed for {user}:\n{out}")
    return out


def parse_duration(text):
    m = re.search(r"rows in set: \(([\d.]+)(ms|s|µs|us|m)\)", text)
    val, unit = float(m.group(1)), m.group(2)
    return val * {"ms": 1, "s": 1e3, "µs": 1e-3, "us": 1e-3, "m": 6e4}[unit]


def parse_row(text):
    rows = [ln for ln in text.splitlines() if ln.startswith("|")]
    vals = [c.strip() for c in rows[-1].strip("|").split("|")]
    return int(float(vals[0])), float(vals[1])


def main():
    global WORK, SCDBCLIENT
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=45222)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--bin", default=str(HERE / "bin"), help="directory with scdbclient and scqltool")
    a = ap.parse_args()
    SCDBCLIENT = Path(a.bin) / "scdbclient"
    scqltool = Path(a.bin) / "scqltool"

    adult_n = len(load_adult())
    recs = load_adult() if a.n == adult_n else scaled(a.n, seed=100)
    WORK = HERE / f"work_{a.n}"
    if WORK.exists():
        sh(["docker", "compose", "-p", PROJECT, "down", "-v"], cwd=WORK)
        shutil.rmtree(WORK)
    shutil.copytree(HERE / "deploy", WORK)

    pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    keys = {}
    for party in ("alice", "bob"):
        conf = WORK / "engine" / party / "conf"
        sh(["docker", "run", "--rm", "-v", f"{conf}:/out", "--entrypoint", "openssl", IMAGE,
            "genpkey", "-algorithm", "ed25519", "-out", "/out/ed25519key.pem"])
        keys[party] = sh(["docker", "run", "--rm", "-v", f"{conf}:/out", "--entrypoint", "sh", IMAGE, "-c",
                          "openssl pkey -in /out/ed25519key.pem -pubout -outform DER | base64 -w0"]).strip()
    render(WORK, {"__MYSQL_ROOT_PASSWD__": pw, "__ALICE_PUBLIC_KEY__": keys["alice"], "__BOB_PUBLIC_KEY__": keys["bob"]})
    write_data(WORK, recs)

    sh(["docker", "compose", "-p", PROJECT, "up", "-d"], cwd=WORK)
    mysql = container("mysql")
    for _ in range(900):
        try:
            got = sh(["docker", "exec", mysql, "mysql", "-uroot", f"-p{pw}", "-N", "-e",
                      "SELECT (SELECT COUNT(*) FROM alice.ta)+(SELECT COUNT(*) FROM bob.tb)"])
            if int(got.split()[-1]) == 2 * len(recs):
                break
        except (subprocess.CalledProcessError, ValueError, IndexError):
            pass
        time.sleep(2)
    else:
        raise RuntimeError("MySQL did not finish loading")
    for _ in range(60):          # SCDB connects to MySQL after it is up
        try:
            scdb("root", "root", "show databases;")
            break
        except subprocess.CalledProcessError:
            time.sleep(2)

    users = {p: sh([str(scqltool), "genCreateUserStmt", "--user", p, "--passwd",
                    {"alice": "some_password", "bob": "another_password"}[p], "--party", p,
                    "--pem", str(WORK / "engine" / p / "conf" / "ed25519key.pem")]).strip().splitlines()[-1]
             for p in ("alice", "bob")}
    scdb("root", "root", "CREATE DATABASE demo;\n" + users["alice"] + ";\n" + users["bob"] + ";\n"
         "GRANT CREATE, GRANT OPTION, DROP ON demo.* TO alice;\nGRANT CREATE, GRANT OPTION, DROP ON demo.* TO bob;\n")
    scdb("alice", "some_password",
         "CREATE TABLE demo.ta (id string, age int, sex string, hours int) REF_TABLE=alice.ta DB_TYPE='mysql';\n"
         "ALTER USER alice WITH ENDPOINT 'engine_alice:8003';\n"
         "GRANT SELECT PLAINTEXT(id, age, sex, hours) ON demo.ta TO alice;\n"
         "GRANT SELECT PLAINTEXT_AFTER_JOIN(id) ON demo.ta TO bob;\n"
         "GRANT SELECT PLAINTEXT_AFTER_COMPARE(age, sex) ON demo.ta TO bob;\n"
         "GRANT SELECT PLAINTEXT_AFTER_AGGREGATE(hours) ON demo.ta TO bob;\n")
    scdb("bob", "another_password",
         "CREATE TABLE demo.tb (id string, education string, marital string, occupation string, race string, "
         "country string) REF_TABLE=bob.tb DB_TYPE='mysql';\n"
         "ALTER USER bob WITH ENDPOINT 'engine_bob:8003';\n"
         "GRANT SELECT PLAINTEXT(id, education, marital, occupation, race, country) ON demo.tb TO bob;\n"
         "GRANT SELECT PLAINTEXT_AFTER_JOIN(id) ON demo.tb TO alice;\n"
         "GRANT SELECT PLAINTEXT_AFTER_COMPARE(education, marital, occupation, race, country) ON demo.tb TO alice;\n")

    ea, eb = container("engine_alice"), container("engine_bob")
    ipa, ipb = ip_of(ea), ip_of(eb)
    out = {"scql_image": IMAGE, "n": len(recs), "runs": []}
    for label, enable in (("loopback", False), ("wan_100mbps_20ms", True)):
        netem(ea, ipb, enable)
        netem(eb, ipa, enable)
        measured_rtt = rtt_ms(ea, ipb)
        for qname, (sql, q) in QUERIES.items():
            exp_c, exp_s = reference(recs, q)
            lat = []
            for i in range(a.reps + 1):                       # first run is a warm-up
                text = scdb("alice", "some_password", f"{sql};\n")
                c, avg = parse_row(text)
                if c != exp_c or abs(avg - exp_s / exp_c) > 1e-3 * max(1.0, exp_s / exp_c):
                    raise AssertionError(f"SCQL wrong on {qname}: {(c, avg)} vs {(exp_c, exp_s / exp_c)}")
                if i:
                    lat.append(parse_duration(text))
            row = {"setting": label, "measured_engine_rtt_ms": measured_rtt, "query": qname,
                   "median_ms": statistics.median(lat), "lat_ms": lat, "count": exp_c}
            out["runs"].append(row)
            print(json.dumps(row), flush=True)
    (HERE.parent / "results" / f"scql_{len(recs)}.json").write_text(json.dumps(out, indent=1))
    sh(["docker", "compose", "-p", PROJECT, "down", "-v"], cwd=WORK)


if __name__ == "__main__":
    main()
