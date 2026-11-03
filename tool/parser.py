"""CSV 解析与入库：自动识别 3 种导出格式，清洗、去重、写库。

支持格式
  A) 7 列 系统日志   : 日期,时间,优先层级,主机名称,分类,程序名称,消息
  B) 8 列 传输日志   : 日志,时间,IP 地址,用户,事件,文件/文件夹,文件大小,文件名称
  C) 9 列 传输日志   : 主机名称,日志,时间,IP 地址,用户,事件,文件/文件夹,文件大小,文件名称
"""
import csv
import os
import re
import sqlite3
from datetime import datetime

EV_MAP = {"read": "读取", "write": "写入", "create": "创建", "delete": "删除",
          "rename": "重命名", "move": "移动", "copy": "复制",
          "login": "登入", "logout": "登出"}

UNITS = {"b": 1, "byte": 1, "bytes": 1, "kb": 1024, "mb": 1024 ** 2,
         "gb": 1024 ** 3, "tb": 1024 ** 4}

RE_SMB = re.compile(
    r"^Event: (?P<ev>[A-Za-z]+),\s*Path: (?P<path>.*),\s*"
    r"File/Folder: (?P<ft>[^,]*),\s*Size: (?P<size>[^,]*),\s*"
    r"User: (?P<user>[^,]*),\s*IP: (?P<ip>[^,]*)\s*$", re.S)
RE_AUTH = re.compile(
    r"^User \[(?P<user>[^\]]*)\] from \[(?P<client>[^(]*)(?:\((?P<ip>[^)]*)\))?\]"
    r" via \[(?P<via>[^\]]*)\] accessed shared folder \[(?P<share>[^\]]*)\]", re.S)
RE_SIGNIN = re.compile(
    r"^User \[(?P<user>[^\]]*)\] from \[(?P<ip>[^\]]*)\]\s+(?P<what>failed to sign in|signed in)",
    re.S | re.I)
RE_LOGOUT = re.compile(
    r"^User \[(?P<user>[^\]]*)\] from \[(?P<client>[^(]*)(?:\((?P<ip>[^)]*)\))?\]"
    r"\s+(?:logged out|has logged out)", re.S | re.I)

DT_FMTS = ("%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
           "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M", "%Y/%m/%d %H:%M")

COLS = ["src", "src_kind", "ts", "date", "hour", "host", "log", "program",
        "event", "prio", "ip", "user", "client", "via", "share",
        "item_type", "size", "path", "new_path", "message"]

DDL = """
CREATE TABLE IF NOT EXISTS logs (
  id        INTEGER PRIMARY KEY,
  src       TEXT, src_kind TEXT, ts TEXT, date TEXT, hour INTEGER,
  host      TEXT, log TEXT, program TEXT, event TEXT, prio TEXT,
  ip        TEXT, user TEXT, client TEXT, via TEXT, share TEXT,
  item_type TEXT, size INTEGER, path TEXT, new_path TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS imports (
  src TEXT PRIMARY KEY, rows INTEGER, skipped INTEGER, bad INTEGER,
  imported_at TEXT, ts_min TEXT, ts_max TEXT
);
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS i_ts    ON logs(ts)",
    "CREATE INDEX IF NOT EXISTS i_date  ON logs(date)",
    "CREATE INDEX IF NOT EXISTS i_user  ON logs(user)",
    "CREATE INDEX IF NOT EXISTS i_event ON logs(event)",
    "CREATE INDEX IF NOT EXISTS i_path  ON logs(path)",
    "CREATE INDEX IF NOT EXISTS i_ip    ON logs(ip)",
    "CREATE INDEX IF NOT EXISTS i_hour  ON logs(hour)",
    "CREATE INDEX IF NOT EXISTS i_src   ON logs(src_kind)",
    "CREATE INDEX IF NOT EXISTS i_srcf  ON logs(src)",
    "CREATE INDEX IF NOT EXISTS i_fp    ON logs(ts,user,event,path,size,item_type)",
]


def parse_size(txt):
    if not txt:
        return None
    m = re.match(r"^([\d.,]+)\s*([A-Za-z]+)$", str(txt).strip())
    if not m:
        return None
    try:
        num = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    mult = UNITS.get(m.group(2).lower())
    return int(num * mult) if mult else None


def parse_dt(s):
    s = (s or "").strip().replace("  ", " ")
    for f in DT_FMTS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass
    return None


def parse_msg(msg):
    out = {k: None for k in ("event", "path", "new_path", "ip", "user",
                             "item_type", "size", "client", "via", "share")}
    if not msg:
        return out
    msg = msg.strip()
    m = RE_SMB.match(msg)
    if m:
        ev = m.group("ev").lower()
        out["event"] = EV_MAP.get(ev, ev)
        p = m.group("path")
        if ev in ("rename", "move") and " -> " in p:
            out["path"], out["new_path"] = p.split(" -> ", 1)
        else:
            out["path"] = p
        out["item_type"] = {"File": "文件", "Folder": "文件夹"}.get(
            m.group("ft").strip(), m.group("ft").strip())
        out["size"] = parse_size(m.group("size"))
        out["user"] = m.group("user").strip() or None
        out["ip"] = m.group("ip").strip() or None
        return out
    m = RE_SIGNIN.match(msg)
    if m:
        out.update(event="登入失败" if m.group("what").lower().startswith("failed") else "登入",
                   user=m.group("user").strip() or None,
                   ip=m.group("ip").strip() or None)
        return out
    m = RE_AUTH.match(msg)
    if m:
        out.update(event="登入", user=m.group("user").strip() or None,
                   ip=(m.group("ip") or "").strip() or None,
                   client=(m.group("client") or "").strip() or None,
                   via=m.group("via").strip() or None,
                   share=m.group("share").strip() or None)
        return out
    m = RE_LOGOUT.match(msg)
    if m:
        out.update(event="登出", user=m.group("user").strip() or None,
                   ip=(m.group("ip") or "").strip() or None,
                   client=(m.group("client") or "").strip() or None)
    return out


def detect_kind(header):
    h = [x.strip() for x in header]
    if "消息" in h and "日期" in h:
        return "all"
    if "主机名称" in h and "时间" in h:
        return "general"
    if "日志" in h and "文件名称" in h:
        return "xfer"
    return None


def connect(db_path):
    con = sqlite3.connect(db_path, timeout=30)
    con.executescript(DDL)
    return con


def row_to_record(header, row, fn, kind):
    d = dict(zip(header, row))
    if kind == "all":
        dt = parse_dt("%s %s" % ((d.get("日期") or "").strip(),
                                 (d.get("时间") or "").strip()))
        msg = (d.get("消息") or "").strip()
        p = parse_msg(msg)
        rec = dict(src=fn, src_kind=kind,
                   host=(d.get("主机名称") or "").strip() or None,
                   log=(d.get("分类") or "").strip() or None,
                   program=(d.get("程序名称") or "").strip() or None,
                   event=p["event"], prio=(d.get("优先层级") or "").strip() or None,
                   ip=p["ip"], user=p["user"], client=p["client"], via=p["via"],
                   share=p["share"], item_type=p["item_type"], size=p["size"],
                   path=p["path"], new_path=p["new_path"], message=msg)
    else:
        dt = parse_dt(d.get("时间"))
        rec = dict(src=fn, src_kind=kind,
                   host=(d.get("主机名称") or "").strip() or "NAS",
                   log=(d.get("日志") or "").strip() or None, program=None,
                   event=(d.get("事件") or "").strip() or None, prio=None,
                   ip=(d.get("IP 地址") or "").strip() or None,
                   user=(d.get("用户") or "").strip() or None,
                   client=None, via=None, share=None,
                   item_type=(d.get("文件/文件夹") or "").strip() or None,
                   size=parse_size(d.get("文件大小")),
                   path=(d.get("文件名称") or "").strip() or None,
                   new_path=None, message=None)
    rec["ts"] = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None
    rec["date"] = dt.strftime("%Y-%m-%d") if dt else None
    rec["hour"] = dt.hour if dt else None
    return rec, (dt is not None)


def import_csv(db_path, src_path, clean_dir=None, progress=None, display_name=None):
    """导入单个 CSV，返回统计 dict。同名 src 会先清空旧数据。"""
    fn = display_name or os.path.basename(src_path)
    con = connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA cache_size=-200000")

    # 探测表头
    header = None
    with open(src_path, encoding="utf-8-sig", newline="", errors="replace") as fh:
        for row in csv.reader(fh):
            if row and any(x.strip() for x in row) and len(row) >= 5:
                header = row
                break
    if header is None:
        raise ValueError("空文件或无法识别表头")
    kind = detect_kind(header)
    if kind is None:
        raise ValueError("表头不认识：%s" % ",".join(header))

    con.execute("DELETE FROM logs WHERE src = ?", (fn,))
    con.commit()

    out_path = os.path.join(clean_dir, fn) if clean_dir else None
    if out_path and os.path.abspath(out_path) == os.path.abspath(src_path):
        out_path = None  # 防自截断
    ofh = open(out_path, "w", encoding="utf-8", newline="") if out_path else None
    writer = csv.writer(ofh, lineterminator="\n") if ofh else None
    if writer:
        writer.writerow(header)

    ins = "INSERT INTO logs (%s) VALUES (%s)" % (
        ",".join(COLS), ",".join("?" * len(COLS)))
    batch, n, skipped, bad = [], 0, 0, 0
    ts_min = ts_max = None
    con.execute("BEGIN")
    with open(src_path, encoding="utf-8-sig", newline="", errors="replace") as fh:
        for row in csv.reader(fh):
            if not row or not any(x.strip() for x in row):
                continue
            if len(row) < 5:
                skipped += 1
                continue
            if row == header:
                skipped += 1
                continue
            if len(row) != len(header):
                # 表头未被识别成行（首行标签被当成表头时）
                if detect_kind(row) == kind:
                    skipped += 1
                    continue
            if writer:
                writer.writerow(row)
            rec, ok = row_to_record(header, row, fn, kind)
            if not ok:
                bad += 1
            else:
                if ts_min is None or rec["ts"] < ts_min:
                    ts_min = rec["ts"]
                if ts_max is None or rec["ts"] > ts_max:
                    ts_max = rec["ts"]
            batch.append(tuple(rec[c] for c in COLS))
            n += 1
            if len(batch) >= 20000:
                con.executemany(ins, batch)
                batch.clear()
                if progress:
                    progress(n)
        if batch:
            con.executemany(ins, batch)
    con.execute("COMMIT")
    if ofh:
        ofh.close()

    deduped = dedupe(con)
    con.execute(
        "INSERT OR REPLACE INTO imports VALUES (?,?,?,?,?,?,?)",
        (fn, n, skipped, bad, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         ts_min, ts_max))
    con.commit()
    total = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    con.close()
    return {"file": fn, "kind": kind, "rows": n, "skipped": skipped,
            "bad_time": bad, "deduped": deduped, "total": total,
            "ts_min": ts_min, "ts_max": ts_max}


def dedupe(con):
    """按 (ts,user,event,path,size,item_type) 去重，保留 id 最小的一条。"""
    before = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    con.execute("""
      DELETE FROM logs WHERE id NOT IN (
        SELECT MIN(id) FROM logs
        GROUP BY ts,user,event,path,size,item_type
      )""")
    con.commit()
    after = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    return before - after


def ensure_indexes(con):
    for s in INDEXES:
        con.execute(s)
    con.commit()
