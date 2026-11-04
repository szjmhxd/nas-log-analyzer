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
    ensure_search(con)
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
    con.execute("DELETE FROM sidx WHERE id NOT IN (SELECT id FROM logs)")
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
    try:
        index_source(con, fn)
    except sqlite3.OperationalError:
        pass  # 索引维护失败不该让整次导入回滚，启动时会自动补齐
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
    con.execute("DROP TABLE IF EXISTS temp._dup")
    con.execute("""CREATE TEMP TABLE _dup AS
        SELECT id FROM logs WHERE id NOT IN (
          SELECT MIN(id) FROM logs
          GROUP BY ts,user,event,path,size,item_type)""")
    con.execute("DELETE FROM logs WHERE id IN (SELECT id FROM temp._dup)")
    con.execute("DELETE FROM sidx WHERE id IN (SELECT id FROM temp._dup)")
    con.execute("DROP TABLE temp._dup")
    con.commit()
    after = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    return before - after


def ensure_indexes(con):
    for s in INDEXES:
        con.execute(s)
    con.commit()


# ---------------- 检索索引 ----------------
# 直接在 logs 上做 LIKE '%关键词%' 要全表扫 2GB，单次约 2 秒，而一次检索要扫 4 次。
# 拆成两张窄表后，目录条件走 dirs（10MB，命中几万条也是毫秒级），
# 文件名条件走 sidx 的覆盖索引，整体降到 0.5 秒以内。
#
#   dirs(did, path)          唯一目录，约 9 万条
#   sidx(id, t, ev, usr, it, nm, did, sh, nm2, did2)
#       nm  = 文件名（路径最后一段）
#       did = 所在目录 id，目录名搜索通过 dirs 反查
#       sh  = 共享目录名（登入类记录没有路径）
#       nm2/did2 = 重命名后的新文件名与新目录（仅重命名类记录有）
SEARCH_DDL = """
CREATE TABLE IF NOT EXISTS dirs(
  did INTEGER PRIMARY KEY, path TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS u_dirs_path ON dirs(path);

CREATE TABLE IF NOT EXISTS sidx(
  id INTEGER PRIMARY KEY, t INTEGER, ev TEXT, usr TEXT, it INTEGER,
  nm TEXT, did INTEGER, sh TEXT, nm2 TEXT, did2 INTEGER);
CREATE INDEX IF NOT EXISTS i_sidx_did  ON sidx(did);
CREATE INDEX IF NOT EXISTS i_sidx_did2 ON sidx(did2) WHERE did2 IS NOT NULL;
CREATE INDEX IF NOT EXISTS i_sidx_nm   ON sidx(nm);
"""


def ts_key(ts):
    """'2026-08-31 11:03:14' → 20260831110314，便于整数比较与排序。"""
    if not ts or len(ts) != 19:
        return 0
    return int(ts.replace("-", "").replace(" ", "").replace(":", ""))


def ensure_search(con):
    con.executescript(SEARCH_DDL)
    con.commit()


def _dir_cache(con):
    return {r[0][:-1]: r[1] for r in con.execute("SELECT path, did FROM dirs")}


def _split_path(path):
    """返回 (文件名, 目录)；目录不含结尾斜杠。"""
    if not path:
        return "", ""
    d, _, f = path.rpartition("/")
    return f, d


def _index_rows(con, rows, cache, batch=None):
    """rows: (id, ts, event, user, item_type, path, new_path, share)"""
    out = batch if batch is not None else []
    for rid, ts, ev, usr, it, path, np, sh in rows:
        nm, d = _split_path(path)
        did = 0
        if d:
            did = cache.get(d)
            if did is None:
                con.execute("INSERT OR IGNORE INTO dirs(path) VALUES(?)", (d + "/",))
                did = con.execute(
                    "SELECT did FROM dirs WHERE path=?", (d + "/",)).fetchone()[0]
                cache[d] = did
        nm2 = did2 = None
        if np:
            nm2, d2 = _split_path(np)
            if d2:
                did2 = cache.get(d2)
                if did2 is None:
                    con.execute("INSERT OR IGNORE INTO dirs(path) VALUES(?)",
                                (d2 + "/",))
                    did2 = con.execute(
                        "SELECT did FROM dirs WHERE path=?", (d2 + "/",)).fetchone()[0]
                    cache[d2] = did2
        out.append((rid, ts_key(ts), ev, usr, 1 if it == "文件夹" else 0,
                    nm, did, sh or "", nm2, did2))
    return out


INSERT_SIDX = "INSERT OR REPLACE INTO sidx VALUES (?,?,?,?,?,?,?,?,?,?)"
COLS_FOR_INDEX = "id,ts,event,user,item_type,path,new_path,share"


def index_source(con, src):
    """把某个来源文件的行补进检索索引（导入后调用）。"""
    ensure_search(con)
    cache = _dir_cache(con)
    cur = con.execute("SELECT %s FROM logs WHERE src=?" % COLS_FOR_INDEX, (src,))
    batch = []
    while True:
        rows = cur.fetchmany(50000)
        if not rows:
            break
        batch = _index_rows(con, rows, cache, [])
        con.executemany(INSERT_SIDX, batch)
        con.commit()
    return len(cache)


def prune_search(con):
    """删掉 logs 里已不存在的索引行（去重、按文件删除之后）。"""
    con.execute("DELETE FROM sidx WHERE id NOT IN (SELECT id FROM logs)")
    con.commit()


def sync_search(con, progress=None):
    """补齐遗漏的索引行。行数一致时直接返回，不做全表比对。"""
    ensure_search(con)
    a = con.execute("SELECT COUNT(*) FROM sidx").fetchone()[0]
    b = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if a == b:
        return 0
    if a > b:
        prune_search(con)
        if a - b < 10000:
            return 0
    cache = _dir_cache(con)
    cur = con.execute(
        "SELECT %s FROM logs WHERE id NOT IN (SELECT id FROM sidx) ORDER BY id"
        % COLS_FOR_INDEX)
    n = 0
    while True:
        rows = cur.fetchmany(50000)
        if not rows:
            break
        con.executemany(INSERT_SIDX, _index_rows(con, rows, cache, []))
        con.commit()
        n += len(rows)
        if progress:
            progress(n)
    return n


def rebuild_search(con, progress=None):
    """整表重建 dirs + sidx。首次安装或结构变更时用。"""
    ensure_search(con)
    con.execute("DROP INDEX IF EXISTS i_sidx_did2")
    con.execute("DELETE FROM sidx")
    con.execute("DELETE FROM dirs")
    con.commit()
    con.execute("CREATE INDEX IF NOT EXISTS i_sidx_did2 ON sidx(did2)"
                " WHERE did2 IS NOT NULL")
    cache = {}
    cur = con.execute("SELECT %s FROM logs ORDER BY id" % COLS_FOR_INDEX)
    n = 0
    while True:
        rows = cur.fetchmany(50000)
        if not rows:
            break
        batch = _index_rows(con, rows, cache, [])
        con.executemany(INSERT_SIDX, batch)
        con.commit()
        n += len(rows)
        if progress:
            progress(n)
    con.execute("ANALYZE sidx")
    con.commit()
    return n
