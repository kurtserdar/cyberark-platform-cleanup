#!/usr/bin/env python3
"""
CyberArk PAM (self-hosted PVWA) platform temizligi.

  1) report      : Salt-okunur. Platform basina hesap sayisi, son kullanim vb. -> CSV
  2) deactivate  : CSV'de Approved=YES olan platformlari pasife alir (geri alinabilir)
  3) delete      : CSV'de Approved=YES olan platformlari yedekleyip siler (GERI ALINAMAZ)

deactivate/delete varsayilan olarak DRY-RUN calisir; gercekten uygulamak icin --execute.

Ornek:
  python cyberark_platform_cleanup.py report --url https://pvwa.firma.local/PasswordVault --user auditor --activities
  python cyberark_platform_cleanup.py deactivate --url ... --user admin --csv platform_report.csv --execute
  python cyberark_platform_cleanup.py delete     --url ... --user admin --csv platform_report.csv --execute

Gereksinim: pip install requests   |   PVWA 11.4+ (Platforms/targets API)
"""
import argparse
import csv
import getpass
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import requests

# Insan/uygulama kullanimi sayilan aktivite anahtar kelimeleri (CPM islemleri haric tutulur)
HUMAN_ACTIONS = ("retrieve", "connect", "use password", "show password", "copy password")

FIELDS = [
    "PlatformID", "Name", "NumericID", "Active", "SystemType", "PlatformBaseID",
    "AccountCount", "SafeCount", "Safes", "CpmManagedCount",
    "NewestAccountCreated", "LastSecretChange", "LastHumanUse", "LastAnyActivity",
    "OnboardingRules", "Suggestion", "Approved",
]


class Pvwa:
    def __init__(self, base, verify):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.verify = verify

    def logon(self, auth, user, password):
        r = self.s.post(
            f"{self.base}/API/auth/{auth}/Logon",
            json={"username": user, "password": password, "concurrentSession": True},
            timeout=60,
        )
        r.raise_for_status()
        self.s.headers["Authorization"] = r.json()

    def logoff(self):
        try:
            self.s.post(f"{self.base}/API/Auth/Logoff", timeout=30)
        except requests.RequestException:
            pass

    def call(self, method, path, **kw):
        r = self.s.request(method, f"{self.base}/{path.lstrip('/')}", timeout=180, **kw)
        r.raise_for_status()
        return r


def day(epoch):
    if not epoch:
        return ""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")


def get_platforms(p):
    return p.call("GET", "API/Platforms/targets").json().get("Platforms", [])


def get_accounts_by_platform(p):
    """Tum hesaplari ceker (kullanicinin gorebildigi kasalar!) ve platformId'ye gore gruplar."""
    grouped, total, path = defaultdict(list), 0, "API/Accounts?limit=1000"
    while path:
        data = p.call("GET", path).json()
        for acc in data.get("value", []):
            grouped[(acc.get("platformId") or "").lower()].append(acc)
            total += 1
        path = data.get("nextLink")
        print(f"\r  hesaplar okunuyor: {total}", end="", file=sys.stderr)
    print(file=sys.stderr)
    return grouped


def get_onboarding_rules(p):
    """Otomatik onboarding kurallari: platformId -> [kural adlari]"""
    rules = defaultdict(list)
    try:
        data = p.call("GET", "API/AutomaticOnboardingRules").json()
        for r in data.get("AutomaticOnboardingRules", []):
            rules[(r.get("TargetPlatformId") or "").lower()].append(r.get("RuleName", "?"))
    except requests.RequestException as e:
        print(f"UYARI: onboarding kurallari okunamadi ({e}); elle kontrol edin.", file=sys.stderr)
    return rules


def account_activity(p, acc_id):
    """(son_insan_kullanimi, son_herhangi_aktivite) epoch; okunamazsa (None, None)"""
    try:
        acts = p.call("GET", f"API/Accounts/{acc_id}/Activities").json().get("Activities", [])
    except requests.RequestException:
        return None, None
    last_any = last_human = 0
    for a in acts:
        d = int(a.get("Date") or 0)
        action = (a.get("Action") or "").lower()
        last_any = max(last_any, d)
        if not action.startswith("cpm") and any(k in action for k in HUMAN_ACTIONS):
            last_human = max(last_human, d)
    return last_human, last_any


def cmd_report(p, args):
    platforms = get_platforms(p)
    accounts = get_accounts_by_platform(p)
    rules = get_onboarding_rules(p)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=args.stale_days)).timestamp()
    known = {(pl.get("PlatformID") or "").lower() for pl in platforms}

    rows = []
    for i, pl in enumerate(sorted(platforms, key=lambda x: x.get("PlatformID", "")), 1):
        pid = pl.get("PlatformID", "")
        accs = accounts.get(pid.lower(), [])
        safes = sorted({a.get("safeName", "") for a in accs})
        last_change = max((int((a.get("secretManagement") or {}).get("lastModifiedTime") or 0) for a in accs), default=0)
        newest = max((int(a.get("createdTime") or 0) for a in accs), default=0)
        cpm = sum(1 for a in accs if (a.get("secretManagement") or {}).get("automaticManagementEnabled"))

        last_human = last_any = None
        if args.activities and accs:
            print(f"\r  aktiviteler: platform {i}/{len(platforms)} ({pid}, {len(accs)} hesap)   ", end="", file=sys.stderr)
            sample = accs if not args.activity_sample else accs[: args.activity_sample]
            last_human = last_any = 0
            for a in sample:
                h, n = account_activity(p, a["id"])
                last_human, last_any = max(last_human, h or 0), max(last_any, n or 0)

        pid_rules = rules.get(pid.lower(), [])
        if not accs and not pid_rules:
            suggestion = "DELETE_CANDIDATE (hesap yok)"
        elif not accs:
            suggestion = "REVIEW (hesap yok ama onboarding kurali var)"
        elif args.activities and max(last_human or 0, last_change, newest) < cutoff:
            suggestion = f"REVIEW_STALE ({args.stale_days} gundur kullanim/degisim yok; once hesaplar tasinmali)"
        else:
            suggestion = "KEEP"

        rows.append({
            "PlatformID": pid, "Name": pl.get("Name", ""), "NumericID": pl.get("ID", ""),
            "Active": pl.get("Active", ""), "SystemType": pl.get("SystemType", ""),
            "PlatformBaseID": pl.get("PlatformBaseID", ""),
            "AccountCount": len(accs), "SafeCount": len(safes),
            "Safes": "; ".join(safes[:10]) + (" ..." if len(safes) > 10 else ""),
            "CpmManagedCount": cpm,
            "NewestAccountCreated": day(newest), "LastSecretChange": day(last_change),
            "LastHumanUse": "n/a" if last_human is None else (day(last_human) or "kayit yok"),
            "LastAnyActivity": "n/a" if last_any is None else (day(last_any) or "kayit yok"),
            "OnboardingRules": "; ".join(pid_rules),
            "Suggestion": suggestion, "Approved": "",
        })
    print(file=sys.stderr)

    with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    orphans = {k: len(v) for k, v in accounts.items() if k not in known}
    print(f"Rapor: {args.csv}  ({len(rows)} platform, "
          f"{sum(1 for r in rows if r['Suggestion'].startswith('DELETE'))} silme adayi)")
    if orphans:
        print("UYARI: hedef platform listesinde olmayan platformId'li hesaplar:", orphans)
    print("Sonraki adim: CSV'yi inceleyin, silinecek satirlarda Approved sutununa YES yazin.")


def cmd_change(p, args, action):
    """action: 'deactivate' veya 'delete'. Her platform icin canli veriden yeniden dogrular."""
    with open(args.csv, newline="", encoding="utf-8-sig") as f:
        approved = [r["PlatformID"] for r in csv.DictReader(f) if (r.get("Approved") or "").strip().upper() == "YES"]
    if not approved:
        sys.exit("CSV'de Approved=YES olan satir yok.")

    live = {(pl.get("PlatformID") or "").lower(): pl for pl in get_platforms(p)}
    accounts = get_accounts_by_platform(p)
    rules = get_onboarding_rules(p)

    mode = "UYGULANIYOR" if args.execute else "DRY-RUN"
    print(f"[{mode}] {action}: {len(approved)} onayli platform")
    if args.execute:
        answer = input(f"Onay icin platform sayisini yazin ({len(approved)}): ")
        if answer.strip() != str(len(approved)):
            sys.exit("Iptal edildi.")
    if action == "delete":
        os.makedirs(args.backup_dir, exist_ok=True)

    log = []
    for pid in approved:
        key, result = pid.lower(), ""
        pl = live.get(key)
        if pl is None:
            result = "SKIP: platform bulunamadi"
        elif accounts.get(key):
            result = f"SKIP: {len(accounts[key])} hesap bagli"
        elif rules.get(key):
            result = f"SKIP: onboarding kurali var ({'; '.join(rules[key])})"
        elif action == "delete" and pl.get("Active") and not args.allow_active:
            result = "SKIP: platform hala aktif (once deactivate + bekleme suresi)"
        else:
            try:
                if action == "delete":
                    # Yedek alinamazsa silme yapilmaz
                    zip_path = os.path.join(args.backup_dir, f"{pid}.zip")
                    r = p.call("POST", f"API/Platforms/{pid}/Export")
                    with open(zip_path, "wb") as f:
                        f.write(r.content)
                    if os.path.getsize(zip_path) == 0:
                        raise RuntimeError("yedek dosyasi bos")
                if not args.execute:
                    result = f"DRY-RUN: {action} yapilacakti"
                elif action == "delete":
                    p.call("DELETE", f"API/Platforms/targets/{pl['ID']}")
                    result = "DELETED"
                else:
                    p.call("POST", f"API/Platforms/targets/{pl['ID']}/deactivate")
                    result = "DEACTIVATED"
            except (requests.RequestException, RuntimeError, OSError) as e:
                detail = getattr(getattr(e, "response", None), "text", "") or ""
                result = f"ERROR: {e} {detail[:200]}"
        print(f"  {pid:40s} {result}")
        log.append({"Time": datetime.now().isoformat(timespec="seconds"), "PlatformID": pid,
                    "Action": action, "Result": result})

    log_path = f"platform_{action}_log_{datetime.now():%Y%m%d_%H%M%S}.csv"
    with open(log_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["Time", "PlatformID", "Action", "Result"])
        w.writeheader()
        w.writerows(log)
    print(f"Log: {log_path}")


def main():
    ap = argparse.ArgumentParser(description="CyberArk platform temizligi")
    ap.add_argument("command", choices=["report", "deactivate", "delete"])
    ap.add_argument("--url", required=True, help="https://pvwa.firma.local/PasswordVault")
    ap.add_argument("--user", required=True)
    ap.add_argument("--auth", default="CyberArk", choices=["CyberArk", "LDAP", "RADIUS", "Windows"])
    ap.add_argument("--csv", default="platform_report.csv")
    ap.add_argument("--stale-days", type=int, default=180)
    ap.add_argument("--activities", action="store_true",
                    help="Hesap basina aktivite logunu oku (yavas: hesap sayisi kadar API cagrisi)")
    ap.add_argument("--activity-sample", type=int, default=0,
                    help="Platform basina en fazla N hesabin aktivitesine bak (0 = hepsi)")
    ap.add_argument("--backup-dir", default="platform_backup")
    ap.add_argument("--allow-active", action="store_true", help="delete: aktif platformu da sil")
    ap.add_argument("--execute", action="store_true", help="Olmadan sadece dry-run")
    ap.add_argument("--ca-bundle", help="Kurumsal CA sertifika dosyasi (PEM)")
    ap.add_argument("--insecure", action="store_true", help="TLS dogrulamasini kapat (onerilmez)")
    args = ap.parse_args()

    verify = False if args.insecure else (args.ca_bundle or True)
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    p = Pvwa(args.url, verify)
    p.logon(args.auth, args.user, getpass.getpass(f"{args.user} parolasi: "))
    try:
        if args.command == "report":
            cmd_report(p, args)
        else:
            cmd_change(p, args, args.command)
    finally:
        p.logoff()


if __name__ == "__main__":
    main()
