"""启动前环境自检。只依赖标准库，本身不能用任何第三方包。

检查项：
  1. Python 版本 >= 3.8
  2. 用到的标准库模块是否齐全（sqlite3 在部分精简版 Python 里会被裁掉）
  3. SQLite 版本是否够用（部分索引用到 3.8+，这里按 3.20 兜底）
  4. 如果仓库根目录存在 requirements.txt，就用 pip 装一遍

退出码：0 通过 / 2 Python 太旧 / 3 缺模块 / 4 依赖安装失败
运行：python tool/preflight.py
"""
import os
import subprocess
import sys

MIN_PY = (3, 8)
MIN_SQLITE = (3, 20)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODULES = [
    ("sqlite3", "数据库（Python 自带的 SQLite 绑定）"),
    ("http.server", "本地 HTTP 服务"),
    ("csv", "CSV 解析"),
    ("json", "接口序列化"),
    ("urllib.parse", "URL 解析"),
]


def fail(code, *lines):
    for ln in lines:
        print(ln)
    print("")
    return code


def check_python():
    if sys.version_info < MIN_PY:
        return fail(
            2,
            "[ERROR] Python 版本过低：当前 %d.%d，需要 %d.%d 或更高。"
            % (sys.version_info[0], sys.version_info[1], MIN_PY[0], MIN_PY[1]),
            "        到 python.org 装一个新版本，安装时勾选 Add Python to PATH。",
        )
    print("  Python   %d.%d.%d  OK" % sys.version_info[:3])
    return 0


def check_modules():
    missing = []
    for name, why in MODULES:
        try:
            __import__(name)
        except ImportError:
            missing.append("%s（%s）" % (name, why))
    if missing:
        return fail(
            3,
            "[ERROR] 当前 Python 缺少这些标准库模块：",
            *["        - " + m for m in missing],
            "",
            "        这些是 Python 自带的，缺了通常是用了精简版 / 嵌入式版解释器，",
            "        换一个官方安装包即可，不需要 pip。",
        )
    print("  标准库   5 个模块齐全  OK")
    return 0


def check_sqlite():
    import sqlite3
    ver = tuple(int(x) for x in sqlite3.sqlite_version.split(".")[:2])
    if ver < MIN_SQLITE:
        return fail(
            3,
            "[ERROR] SQLite 版本过低：当前 %s，需要 %d.%d 或更高。"
            % (sqlite3.sqlite_version, MIN_SQLITE[0], MIN_SQLITE[1]),
        )
    print("  SQLite   %s  OK" % sqlite3.sqlite_version)
    return 0


def install_requirements():
    """第三方依赖是可选的：目前工具本体只用标准库，正常走不到这里。"""
    req = os.path.join(BASE, "requirements.txt")
    if not os.path.exists(req):
        print("  第三方依赖 无（纯标准库）")
        return 0
    todo = []
    with open(req, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if line:
                todo.append(line)
    if not todo:
        print("  第三方依赖 无（requirements.txt 是空的）")
        return 0

    print("  第三方依赖 %d 项，开始安装…" % len(todo))
    cmd = [sys.executable, "-m", "pip", "install", "-r", req]
    try:
        rc = subprocess.call(cmd)
    except OSError as e:
        return fail(4, "[ERROR] 调不起 pip：%s" % e,
                    "        手动执行：%s -m pip install -r requirements.txt"
                    % sys.executable)
    if rc != 0:
        return fail(
            4,
            "[ERROR] 依赖安装失败（pip 退出码 %d）。" % rc,
            "        网络不通可以先配镜像再重试：",
            "        %s -m pip install -r requirements.txt "
            "-i https://pypi.tuna.tsinghua.edu.cn/simple" % sys.executable,
        )
    print("  第三方依赖 安装完成  OK")
    return 0


def main():
    print("环境自检")
    for step in (check_python, check_modules, check_sqlite, install_requirements):
        code = step()
        if code:
            return code
    print("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
