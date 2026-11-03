"""生成完全虚构的示例数据，用于演示三种导出格式的识别与清洗。

生成物（都是假的，人名 / 目录 / 文件名均为示意）：
  general_2026-06.csv   9 列格式，2026-06-01 ~ 06-28
  system_2026-07.csv    7 列格式，2026-07-01 ~ 07-20，消息里是 SMB / 认证原文

刻意保留了两种真实导出里常见的脏数据：
  - 文件开头多一行分类标签（全部）
  - 中间夹一页重复表头
运行：python sample/make_sample.py
"""
import csv
import os
import random
from datetime import datetime, timedelta

random.seed(20260601)
HERE = os.path.dirname(os.path.abspath(__file__))

USERS = ["alice", "bob", "carol", "dave"]
IPS = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13", "dave": "10.0.0.14"}
FOLDERS = {
    "/team/alpha/design": ["wireframe.pdf", "mockup.png", "style-guide.pdf"],
    "/team/alpha/docs": ["spec.docx", "meeting-notes.md", "release-plan.xlsx"],
    "/team/beta/reports": ["q2-summary.xlsx", "chart.png", "review.pdf"],
    "/team/beta/contracts": ["agreement.pdf", "appendix.docx"],
    "/public/handbook": ["onboarding.pdf", "faq.md"],
}
EVENTS = [("读取", 62), ("写入", 14), ("创建", 12), ("删除", 4), ("重命名", 5), ("移动", 3)]


def pick_event():
    pool = [e for e, w in EVENTS for _ in range(w)]
    return random.choice(pool)


def human_size(n):
    if n >= 1024 ** 2:
        return "%.2f MB" % (n / 1024 ** 2)
    return "%.2f KB" % (n / 1024)


def gen_general():
    rows = []
    day = datetime(2026, 6, 1)
    end = datetime(2026, 6, 28)
    while day <= end:
        weekend = day.weekday() >= 5
        n = random.randint(4, 14) if weekend else random.randint(28, 68)
        if day.strftime("%Y-%m-%d") == "2026-06-15":
            n = int(n * 2.6)          # 刻意留一个尖峰，用来演示对数轴
        for _ in range(n):
            user = random.choice(USERS)
            folder = random.choice(list(FOLDERS))
            name = random.choice(FOLDERS[folder])
            ts = day + timedelta(minutes=random.randint(480, 1150),
                                 seconds=random.randint(0, 59))
            ev = pick_event()
            size = human_size(random.randint(3 * 1024, 9 * 1024 ** 2))
            rows.append(["NAS", "SMB", ts.strftime("%m/%d/%Y %H:%M:%S"),
                         IPS[user], user, ev, "文件", size,
                         "%s/%s" % (folder, name)])
        day += timedelta(days=1)

    path = os.path.join(HERE, "general_2026-06.csv")
    header = ["主机名称", "日志", "时间", "IP 地址", "用户", "事件",
              "文件/文件夹", "文件大小", "文件名称"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write("全部\n")                     # 真实导出里的分类标签行
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(header)
        for i, r in enumerate(rows):
            if i == len(rows) // 2:
                w.writerow(header)          # 分页导出留下的重复表头
            w.writerow(r)
    return path, len(rows)


def gen_system():
    """7 列系统日志：文件操作与登录信息都压在「消息」一列里。"""
    rows = []
    day = datetime(2026, 7, 1)
    end = datetime(2026, 7, 20)
    while day <= end:
        for _ in range(random.randint(10, 40)):
            user = random.choice(USERS)
            ts = day + timedelta(minutes=random.randint(500, 1120),
                                 seconds=random.randint(0, 59))
            roll = random.random()
            if roll < 0.06:               # 登录 / 登出
                if random.random() < 0.5:
                    msg = ("User [%s] from [PC-%s(%s)] via [CIFS(SMB3)] "
                           "accessed shared folder [team]." % (user, user.upper(), IPS[user]))
                else:
                    msg = "User [%s] from [%s] signed in." % (user, IPS[user])
                rows.append([ts.strftime("%Y/%m/%d %H:%M:%S"), "信息", "NAS",
                             "user", "auth", msg])
                continue
            folder = random.choice(list(FOLDERS))
            name = random.choice(FOLDERS[folder])
            ev = pick_event()
            path = "%s/%s" % (folder, name)
            if ev in ("重命名", "移动"):
                newname = "2026-" + name
                newpath = "%s/%s" % (folder, newname)
                smb = "rename"
                p = "%s -> %s" % (path, newpath)
            else:
                smb = {"读取": "read", "写入": "write", "创建": "create",
                       "删除": "delete"}[ev]
                p = path
            size = human_size(random.randint(3 * 1024, 9 * 1024 ** 2))
            msg = ("Event: %s, Path: %s, File/Folder: File, Size: %s, "
                   "User: %s, IP: %s" % (smb, p, size, user, IPS[user]))
            rows.append([ts.strftime("%Y/%m/%d %H:%M:%S"), "信息", "NAS",
                         "user", "SMB", msg])
        day += timedelta(days=1)

    path = os.path.join(HERE, "system_2026-07.csv")
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write("全部\n")
        w = csv.writer(f, lineterminator="\r\n")
        w.writerow(["日期", "时间", "优先层级", "主机名称", "分类", "程序名称", "消息"])
        for r in rows:
            w.writerow([r[0].split(" ")[0], r[0].split(" ")[1], r[1], r[2], r[3], r[4], r[5]])
    return path, len(rows)


if __name__ == "__main__":
    for p, n in (gen_general(), gen_system()):
        print("%s  %d 行" % (os.path.basename(p), n))
