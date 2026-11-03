"""NAS 日志分析台 · 本地服务
启动: python server.py  然后浏览器打开 http://127.0.0.1:8777
"""
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
    c = conn()
    try:
        n = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        mx = c.execute("SELECT MAX(id) FROM logs").fetchone()[0] or 0
        return "%d:%d" % (n, mx)
    finally:
        c.close()


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


def api_search(p):
    where, args = [], []
    kw = (p.get("q") or "").strip()
    if kw:
        # 支持多关键词，全部命中（AND）
        for term in [t for t in kw.split() if t]:
            where.append("(path LIKE ? OR new_path LIKE ? OR message LIKE ? "
                         "OR share LIKE ?)")
            args += ["%" + term + "%"] * 4
    if p.get("user"):
        where.append("user = ?")
        args.append(p["user"])
    if p.get("event"):
        where.append("event = ?")
        args.append(p["event"])
    if p.get("ip"):
        where.append("ip = ?")
        args.append(p["ip"])
    if p.get("from"):
        where.append("date >= ?")
        args.append(p["from"])
    if p.get("to"):
        where.append("date <= ?")
        args.append(p["to"])
    w = ("WHERE " + " AND ".join(where)) if where else ""
    limit = min(int(p.get("limit", 300)), 2000)
    offset = int(p.get("offset", 0))
    c = conn()
    try:
        total = c.execute("SELECT COUNT(*) FROM logs " + w, args).fetchone()[0]
        rows = [dict(r) for r in c.execute(
            "SELECT id,ts,date,user,ip,event,item_type,size,path,new_path,src_kind "
            "FROM logs " + w + " ORDER BY ts DESC LIMIT ? OFFSET ?",
            args + [limit, offset])]
        agg = [dict(r) for r in c.execute(
            "SELECT event, COUNT(*) n FROM logs " + w +
            " GROUP BY event ORDER BY n DESC", args)]
        who = [dict(r) for r in c.execute(
            "SELECT user, COUNT(*) n FROM logs " + w +
            " GROUP BY user ORDER BY n DESC LIMIT 8", args)]
        return {"total": total, "rows": rows, "events": agg, "users": who,
                "limit": limit, "offset": offset}
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
    if backfill_imports():
        clear_overview_cache()   # 元数据变了，缓存作废
    warm_overview()              # 后台先把概览算好，前端打开即出图
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("=" * 46)
    print("  NAS 日志分析台已启动")
    print("  浏览器打开:  http://127.0.0.1:%d" % PORT)
    print("  数据库:      %s" % DB)
    print("  按 Ctrl+C 停止")
    print("=" * 46)
    if os.environ.get("NO_BROWSER") != "1":
        threading.Timer(1.2, lambda: webbrowser.open(
            "http://127.0.0.1:%d" % PORT)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
