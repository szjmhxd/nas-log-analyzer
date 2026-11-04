"""NAS 日志分析台 · 本地服务
启动: python server.py  然后浏览器打开 http://127.0.0.1:8777
"""
import bisect
import json
import os
import sqlite3
import sys
import threading
import urllib.parse
import webbrowser
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parser as P

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(BASE, "logs.db")
CLEAN = os.path.join(BASE, "clean")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PORT = int(os.environ.get("PORT", 8777))
IMPORT_LOCK = threading.Lock()

os.makedirs(CLEAN, exist_ok=True)


def conn():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=()):
    c = conn()
    try:
        return [dict(r) for r in c.execute(sql, args)]
    finally:
        c.close()


# ---------------- 概览缓存 ----------------
# 概览要对 200 万行做多次全表聚合，单次约 4~7 秒。数据只在导入/删除时变化，
# 因此结果缓存在内存 + 磁盘，用 (总行数, 最大 id) 做戳，变了才重算。
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
CACHE_FILE = os.path.join(CACHE_DIR, "overview.json")
_OV = {"stamp": None, "data": None}
_OV_LOCK = threading.Lock()   # 避免预热和请求同时算两遍


def db_stamp():
    """数据库指纹，用来判断缓存是否还新鲜。

    只看行数是不够的：删掉一个来源再导入同样多的行，行数一模一样，
    但内容全换了，缓存会拿旧数据算谱系，把不相干的文件串到一起。
    所以把库文件（含 WAL）的修改时间也带上。
    """
    c = conn()
    try:
        n = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        mx = c.execute("SELECT MAX(id) FROM logs").fetchone()[0] or 0
    finally:
        c.close()
    tag = []
    for f in (DB, DB + "-wal"):
        try:
            st = os.stat(f)
            tag.append("%d.%d" % (st.st_mtime_ns, st.st_size))
        except OSError:
            pass
    return "%d:%d:%s" % (n, mx, ",".join(tag))


def clear_overview_cache():
    _OV["stamp"] = None
    _OV["data"] = None
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
    except OSError:
        pass


def warm_overview():
    """导入/删除后后台预热，用户打开概览时就是即时返回。"""
    def run():
        try:
            api_overview()
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


def api_overview(force=False):
    with _OV_LOCK:
        return _overview_locked(force)


def _overview_locked(force=False):
    stamp = db_stamp()
    if not force:
        if _OV["data"] is not None and _OV["stamp"] == stamp:
            return _OV["data"]
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, encoding="utf-8") as f:
                    c = json.load(f)
                if c.get("stamp") == stamp and c.get("data"):
                    _OV["stamp"] = stamp
                    _OV["data"] = c["data"]
                    return _OV["data"]
            except (OSError, ValueError):
                pass
    data = _compute_overview()
    _OV["stamp"] = stamp
    _OV["data"] = data
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"stamp": stamp, "data": data}, f, ensure_ascii=False)
    except OSError:
        pass
    return data


def _compute_overview():
    c = conn()
    try:
        total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        rng = c.execute("SELECT MIN(date), MAX(date) FROM logs").fetchone()
        first, last = rng[0], rng[1]
        # 五个日聚合合并为一次扫描，比拆成两条快一倍
        daily = [dict(r) for r in c.execute("""
            SELECT date, COUNT(*) n,
                   COUNT(DISTINCT user) users,
                   SUM(CASE WHEN event='删除' THEN 1 ELSE 0 END) dels,
                   SUM(CASE WHEN event IN ('登入','登入失败') THEN 1 ELSE 0 END) logins
            FROM logs GROUP BY date ORDER BY date""")]
        have = {d["date"] for d in daily}
        missing = []
        if first and last:
            d = date.fromisoformat(first)
            end = date.fromisoformat(last)
            while d <= end:
                if d.isoformat() not in have:
                    missing.append(d.isoformat())
                d += timedelta(days=1)
        events = [dict(r) for r in c.execute(
            "SELECT event, COUNT(*) n FROM logs GROUP BY event ORDER BY n DESC")]
        users = [dict(r) for r in c.execute("""
            SELECT user, COUNT(*) n, COUNT(DISTINCT date) days
            FROM logs GROUP BY user ORDER BY n DESC LIMIT 12""")]
        hours = [dict(r) for r in c.execute(
            "SELECT hour, COUNT(*) n FROM logs GROUP BY hour ORDER BY hour")]
        files = [dict(r) for r in c.execute(
            "SELECT * FROM imports ORDER BY ts_min")]
        user_count = c.execute("SELECT COUNT(DISTINCT user) FROM logs").fetchone()[0]
        ip_count = c.execute("SELECT COUNT(DISTINCT ip) FROM logs").fetchone()[0]
        path_count = c.execute("SELECT COUNT(DISTINCT path) FROM logs").fetchone()[0]
        cal = 0
        if first and last:
            cal = (date.fromisoformat(last) - date.fromisoformat(first)).days + 1
        return {"total": total, "first": first, "last": last,
                "dayCount": len(daily), "calendarDays": cal,
                "missing": missing, "daily": daily, "events": events,
                "users": users, "hours": hours, "files": files,
                "userCount": user_count, "ipCount": ip_count,
                "pathCount": path_count,
                "dbSize": os.path.getsize(DB) if os.path.exists(DB) else 0}
    finally:
        c.close()


_LIN = {"stamp": None, "parent": {}, "func": None}


def _find(par, x):
    root = x
    while True:
        p = par.get(root)
        if p is None or p == root:
            break
        root = p
    # 路径压缩
    while x != root:
        nxt = par.get(x, root)
        par[x] = root
        x = nxt
    return root


def _split(p):
    d, _, f = (p or "").rpartition("/")
    return d, f


def lineage(c):
    """把"同一份文件"的多次记录串成一个谱系。

    两步：
    1) 目录改名会连带改变所有子文件的路径（A 文件夹 → B 文件夹），
       按时间把子路径回写成改名前的形式；
    2) 文件自身的重命名 / 移动，沿改名链回溯到最早的名字。

    为什么不用简单并查集：`新建文件夹` 这种名字会被反复使用，
    直接合并会把几百个互不相干的文件串成一条。
    这里给"根名字"附加代次（该名字下一次被改走的时间），
    同一份文件始终落在同一个 (名字, 代次) 上。
    """
    stamp = db_stamp()
    if _LIN["stamp"] == stamp:
        return _LIN["func"]

    by_new = {}          # 新目录 → [(时间, 旧目录)]，用于把子路径改写回改名前的目录
    for ts, a, b in c.execute(
            "SELECT ts, path, new_path FROM logs "
            "WHERE item_type='文件夹' AND new_path IS NOT NULL AND new_path<>'' "
            "AND event IN ('重命名','移动')"):
        if a and b:
            by_new.setdefault(b, []).append((ts, a))

    def canon(path, ts):
        """把目录改名之前的路径形式还原出来，最多回溯 5 层。"""
        for _ in range(5):
            d, f = _split(path)
            hit = None
            while d:
                cands = by_new.get(d)
                if cands:
                    best = None
                    for t0, old in cands:
                        if t0 <= ts and (best is None or t0 > best[0]):
                            best = (t0, old)
                    if best:
                        hit = best[1]
                        break
                d, _ = _split(d)
            if not hit:
                break
            path = hit + "/" + f
        return path

    # 改名/移动边一律用"规范化后的路径"作键，否则同一条链会因目录改名断掉
    into = {}
    outof = {}
    for ts, a, b in c.execute(
            "SELECT ts, path, new_path FROM logs "
            "WHERE new_path IS NOT NULL AND new_path<>'' "
            "AND event IN ('重命名','移动')"):
        if not a or not b:
            continue
        ca, cb = canon(a, ts), canon(b, ts)
        into.setdefault(cb, []).append((ts, ca))
        outof.setdefault(ca, []).append(ts)

    for lst in outof.values():
        lst.sort()

    def lin(path, ts):
        if not path:
            return ""
        ts = ts or ""
        path = canon(path, ts)
        for _ in range(6):
            ins = into.get(path)
            if not ins:
                break
            best = None
            for t0, old in ins:
                if t0 <= ts and (best is None or t0 > best[0]):
                    best = (t0, old)
            if not best or best[1] == path:
                break
            path, ts = best[1], best[0]
        outs = outof.get(path)
        if outs:
            i = bisect.bisect_left(outs, ts)
            gen = outs[i] if i < len(outs) else outs[-1]
            return path + "\x00" + gen
        return path

    _LIN["stamp"] = stamp
    _LIN["func"] = lin
    return lin


def _search_where(p):
    """把筛选条件编译成 sidx 上的 WHERE 片段（时间用整数键，省一次转换）。"""
    f, a = [], []
    if p.get("user"):
        f.append("usr = ?")
        a.append(p["user"])
    if p.get("event"):
        f.append("ev = ?")
        a.append(p["event"])
    typ = (p.get("type") or "").strip()
    if typ == "file":
        f.append("it = 0")
    elif typ == "folder":
        f.append("it = 1")
    if p.get("from"):
        try:
            f.append("t >= ?")
            a.append(int(p["from"].replace("-", "")) * 1000000)
        except ValueError:
            pass
    if p.get("to"):
        try:
            f.append("t <= ?")
            a.append(int(p["to"].replace("-", "")) * 1000000 + 235959)
        except ValueError:
            pass
    return (" AND " + " AND ".join(f)) if f else "", a


# 一次检索最多收这么多命中行再在内存里汇总；超过就标记为"至少这么多"
CAP = 300000


def api_search(p):
    terms = [t for t in (p.get("q") or "").split() if t]
    fw, fa = _search_where(p)
    c = conn()
    try:
        # 没有关键词时只有筛选条件，直接走 sidx 顺序扫描
        hit = None
        for term in terms:
            kw = "%" + term + "%"
            # sh / nm2 只在一小部分行上有值，用 <>'' 先短路，省掉 200 万次无用匹配
            cur = c.execute(
                "SELECT id,t,ev,usr,it FROM sidx "
                "WHERE nm LIKE ? OR usr LIKE ? "
                "   OR (sh<>'' AND sh LIKE ?) "
                "   OR (nm2 IS NOT NULL AND nm2 LIKE ?) "
                + fw + " LIMIT %d" % CAP, [kw, kw, kw, kw] + fa)
            got = {r[0]: r for r in cur}
            # 目录名命中：用 dirs 反查（9 万行，毫秒级），比在 200 万行路径里扫快几十倍
            cur = c.execute(
                "SELECT id,t,ev,usr,it FROM sidx "
                "WHERE did IN (SELECT did FROM dirs WHERE path LIKE ?) "
                "   OR did2 IN (SELECT did FROM dirs WHERE path LIKE ?) "
                + fw + " LIMIT %d" % CAP, [kw, kw] + fa)
            for r in cur:
                got.setdefault(r[0], r)
            hit = got if hit is None else {k: v for k, v in hit.items() if k in got}
            if not hit:
                break

        if hit is None:
            cur = c.execute(
                "SELECT id,t,ev,usr,it FROM sidx WHERE 1=1 " + fw +
                " ORDER BY t DESC LIMIT %d" % CAP, fa)
            hit = {r[0]: r for r in cur}

        total = len(hit)
        truncated = total >= CAP
        events = {}
        users = {}
        for r in hit.values():
            events[r[2]] = events.get(r[2], 0) + 1
            if r[3]:
                users[r[3]] = users.get(r[3], 0) + 1

        limit = min(int(p.get("limit", 300)), 5000)
        offset = int(p.get("offset", 0))
        ordered = sorted(hit.values(), key=lambda r: -r[1])
        page = ordered[offset:offset + limit]

        rows = []
        if page:
            ids = [r[0] for r in page]
            ph = ",".join("?" * len(ids))
            det = {r["id"]: dict(r) for r in c.execute(
                "SELECT id,ts,date,user,ip,event,item_type,size,path,new_path,src_kind "
                "FROM logs WHERE id IN (%s)" % ph, ids)}
            for r in page:
                d = det.get(r[0])
                if not d:
                    continue
                rows.append(d)

        # 谱系：把 重命名A→B 之后对 B 的操作并回 A，避免同一个文件被拆成两条
        lin = lineage(c)
        for d in rows:
            d["lin"] = lin(d.get("new_path") or d.get("path") or "",
                           d.get("ts") or "")

        ev = sorted(({"event": k, "n": v} for k, v in events.items()),
                    key=lambda x: -x["n"])
        who = sorted(({"user": k, "n": v} for k, v in users.items()),
                     key=lambda x: -x["n"])[:8]
        return {"total": total, "truncated": truncated, "rows": rows,
                "events": ev, "users": who, "limit": limit, "offset": offset}
    finally:
        c.close()


BLOCKED = ("insert", "update", "delete", "drop", "alter", "create",
           "attach", "detach", "pragma", "vacuum", "replace")


def api_sql(sql):
    s = sql.strip().rstrip(";")
    low = s.lower()
    first_word = low.split(None, 1)[0] if low else ""
    if first_word not in ("select", "with"):
        raise ValueError("只允许 SELECT / WITH 查询。删除数据请在「文件」页操作。")
    if any((" %s " % b) in (" %s " % low) for b in BLOCKED):
        raise ValueError("查询里包含写操作关键字，已拒绝。")
    c = conn()
    try:
        cur = c.execute(s)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [list(r) for r in cur.fetchmany(500)]
        return {"cols": cols, "rows": rows}
    finally:
        c.close()


def api_files():
    c = conn()
    try:
        return [dict(r) for r in c.execute(
            "SELECT * FROM imports ORDER BY ts_min")]
    finally:
        c.close()


def api_delete(src):
    with IMPORT_LOCK:
        c = conn()
        try:
            c.execute("DELETE FROM logs WHERE src = ?", (src,))
            deleted = c.total_changes
            c.execute("DELETE FROM imports WHERE src = ?", (src,))
            c.execute("DELETE FROM sidx WHERE id NOT IN (SELECT id FROM logs)")
            c.commit()
            left = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        finally:
            c.close()
    clear_overview_cache()
    warm_overview()
    return {"deleted": deleted, "total": left}


TMPDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tmp")


def api_import(name, body):
    safe = os.path.basename(name).replace("..", "_").strip() or "upload.csv"
    if not safe.lower().endswith(".csv"):
        raise ValueError("只支持 .csv 文件")
    if not body:
        raise ValueError("文件为空")
    os.makedirs(TMPDIR, exist_ok=True)
    tmp = os.path.join(TMPDIR, safe)
    with open(tmp, "wb") as f:
        f.write(body)
    with IMPORT_LOCK:
        try:
            res = P.import_csv(DB, tmp, CLEAN, display_name=safe)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    clear_overview_cache()
    warm_overview()          # 后台重算，用户点开概览时不用等
    res["file"] = safe
    return res


# ---------------- HTTP ----------------

MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
        ".png": "image/png", ".ico": "image/x-icon"}


class Server(ThreadingHTTPServer):
    # Windows 下 SO_REUSEADDR 会让两个进程抢同一个端口而不报错，
    # 结果新服务绑上了、请求却被老进程接走。这里关掉它，冲突就直接抛错换端口。
    allow_reuse_address = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(u.query)
        p = {k: v[0] for k, v in p.items()}
        try:
            if u.path in ("/", "/index.html"):
                return self._file(os.path.join(STATIC, "index.html"))
            if u.path.startswith("/static/"):
                return self._file(os.path.join(STATIC, u.path[8:]))
            if u.path == "/api/overview":
                return self._send(200, api_overview())
            if u.path == "/api/search":
                return self._send(200, api_search(p))
            if u.path == "/api/files":
                return self._send(200, api_files())
            if u.path == "/api/export":
                return self._export(p)
            if u.path == "/api/ping":
                return self._send(200, {"ok": True, "db": os.path.exists(DB)})
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        p = dict(urllib.parse.parse_qsl(u.query))
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            if u.path == "/api/import":
                return self._send(200, api_import(p.get("name", "upload.csv"), body))
            if u.path == "/api/sql":
                return self._send(200, api_sql(json.loads(body or b"{}").get("sql", "")))
            if u.path == "/api/delete":
                return self._send(200, api_delete(json.loads(body or b"{}").get("src", "")))
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def _file(self, path):
        path = os.path.normpath(path)
        if not path.startswith(STATIC) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        ext = os.path.splitext(path)[1].lower()
        with open(path, "rb") as f:
            data = f.read()
        self._send(200, data, MIME.get(ext, "application/octet-stream"))

    def _export(self, p):
        if p.get("q") is not None or p.get("user"):
            res = api_search({**p, "limit": 5000, "offset": 0})
            cols = ["ts", "user", "ip", "event", "item_type", "size", "path", "new_path"]
            rows = [[r.get(k) for k in cols] for r in res["rows"]]
        else:
            sql = p.get("sql", "SELECT * FROM logs LIMIT 100")
            r = api_sql(sql)
            cols, rows = r["cols"], r["rows"]
        import csv as _csv
        import io
        buf = io.StringIO()
        w = _csv.writer(buf)
        w.writerow(cols)
        w.writerows(rows)
        data = ("\ufeff" + buf.getvalue()).encode("utf-8")
        self._send(200, data, "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="export.csv"'})


def backfill_imports():
    """老库没有 imports 元数据时，按 logs 反推补上；顺带清掉孤儿记录。"""
    c = conn()
    try:
        changed = c.total_changes
        c.execute("""DELETE FROM imports WHERE src NOT IN
                     (SELECT DISTINCT src FROM logs WHERE src IS NOT NULL)""")
        changed = c.total_changes - changed
        c.commit()
        has = c.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
        total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        if has or not total:
            return changed
        rows = c.execute("""SELECT src, COUNT(*) n, MIN(ts), MAX(ts)
                            FROM logs WHERE src IS NOT NULL GROUP BY src""").fetchall()
        for r in rows:
            c.execute("INSERT OR REPLACE INTO imports VALUES (?,?,?,?,?,?,?)",
                      (r[0], r[1], 0, 0, "-", r[2], r[3]))
        changed += len(rows)
        c.commit()
        return changed
    finally:
        c.close()


def main():
    if not os.path.exists(DB):
        print("未找到 logs.db，请先运行 build_db.py")
    P.ensure_indexes(P.connect(DB))
    try:
        P.sync_search(P.connect(DB))
    except sqlite3.OperationalError as e:
        print("检索索引自检失败：%s" % e)
    if backfill_imports():
        clear_overview_cache()   # 元数据变了，缓存作废
    warm_overview()              # 后台先把概览算好，前端打开即出图
    threading.Thread(target=lambda: lineage(conn()), daemon=True).start()
    # 先试默认端口；被占用（或落在 Windows 保留端口段里）就依次试几个相邻端口，
    # 都不行再让系统分配，免得每次重启都换一个记不住的随机端口。
    srv = None
    for p in [PORT] + [PORT + i for i in range(1, 6)] + [8081, 8090, 0]:
        try:
            srv = Server(("127.0.0.1", p), Handler)
            port = srv.server_address[1]
            if p not in (PORT, 0):
                print("[提示] %d 端口被占用，改用 http://127.0.0.1:%d" % (PORT, port))
            break
        except OSError:
            continue
    if srv is None:
        print("[ERROR] 找不到可用的本地端口")
        return
    print("=" * 46)
    print("  NAS 日志分析台已启动")
    print("  浏览器打开:  http://127.0.0.1:%d" % port)
    print("  数据库:      %s" % DB)
    print("  按 Ctrl+C 停止")
    print("=" * 46, flush=True)
    if os.environ.get("NO_BROWSER") != "1":
        threading.Timer(1.2, lambda: webbrowser.open(
            "http://127.0.0.1:%d" % port)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
