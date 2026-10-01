"""PhishLnk-Inspector: Windows LNK kısayolları için statik analiz CLI aracı."""

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import LnkParse3
from rich.console import Console
from rich.table import Table

console = Console()

# LOLBAS kapsamındaki yaygın Windows araçları; argümanlarda büyük/küçük harf duyarsız aranır.
SUSPICIOUS_TOOLS = (
    "powershell",
    "pwsh",
    "cmd",
    "curl",
    "mshta",
    "bitsadmin",
    "certutil",
    "wscript",
    "cscript",
)

# URL ve alan adı desenleri; IP adresleri ayrı olarak doğrulanır.
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|ftp://)[^\s\"'<>]+")
DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::\d{1,5})?(?![\w.-])"
)
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_PATTERN = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
ENCODED_COMMAND_PATTERN = re.compile(
    r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+['\"]?([A-Za-z0-9+/=_-]+)"
)
NON_DOMAIN_SUFFIXES = {"exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "hta"}


# LNK içeriğini LnkParse3 ile okur ve ham parse verisini döndürür.
def parse_lnk(lnk_path: Path) -> Dict[str, Any]:
    with lnk_path.open("rb") as lnk_file:
        parsed_lnk = LnkParse3.lnk_file(lnk_file)
        return parsed_lnk.get_json()


# Parser verisinden hedef yolu ve kısayol komut satırı argümanlarını seçer.
def extract_shortcut_fields(parsed: Dict[str, Any]) -> Tuple[str, str]:
    data = parsed.get("data", {})
    link_info = parsed.get("link_info", {})
    location_info = link_info.get("location_info", {})

    target = (
        link_info.get("local_base_path_unicode")
        or link_info.get("local_base_path")
        or location_info.get("net_name_unicode")
        or location_info.get("net_name")
        or link_info.get("location")
        or data.get("relative_path")
        or "Belirlenemedi"
    )
    suffix = link_info.get("common_path_suffix_unicode") or link_info.get(
        "common_path_suffix"
    )
    if suffix and suffix not in target:
        target = str(target).rstrip("\\/") + "\\" + str(suffix).lstrip("\\/")

    arguments = data.get("command_line_arguments") or ""
    return str(target), str(arguments)


# Komut dizisinde bilinen LOLBAS araçlarını ve şüpheli işaretleri bulur.
def detect_suspicious_tools(command: str) -> List[str]:
    lowered = command.lower()
    return [tool for tool in SUSPICIOUS_TOOLS if re.search(rf"(?<![\w.-]){re.escape(tool)}(?:\.exe)?(?![\w.-])", lowered)]


# -enc / -EncodedCommand parametresindeki PowerShell Base64 içeriğini çözer.
def decode_encoded_commands(command: str) -> List[str]:
    decoded_commands: List[str] = []
    for match in ENCODED_COMMAND_PATTERN.finditer(command):
        encoded = match.group(1).replace("-", "+").replace("_", "/")
        encoded += "=" * (-len(encoded) % 4)
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue

        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding).strip("\x00\ufeff \t\r\n")
            except UnicodeDecodeError:
                continue
            if decoded and decoded not in decoded_commands:
                decoded_commands.append(decoded)
                break
    return decoded_commands


# Komut metninden URL'leri, alan adlarını ve geçerli IPv4/IPv6 adreslerini çıkarır.
def extract_indicators(text: str) -> Dict[str, List[str]]:
    urls = {match.rstrip(".,;)]}") for match in URL_PATTERN.findall(text)}
    text_without_urls = URL_PATTERN.sub(" ", text)
    domains = {
        match.rstrip(".,;)]}") for match in DOMAIN_PATTERN.findall(text_without_urls)
    }
    domains = {domain for domain in domains if not domain.lower().startswith(("http://", "https://", "ftp://"))}
    domains = {
        domain
        for domain in domains
        if domain.rsplit(".", 1)[-1].split(":", 1)[0].lower()
        not in NON_DOMAIN_SUFFIXES
    }
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            domains.add(parsed_url.hostname)

    ips = set()
    for candidate in IP_PATTERN.findall(text) + IPV6_PATTERN.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        ips.add(candidate)

    return {
        "urls": sorted(urls, key=str.lower),
        "domains": sorted(domains, key=str.lower),
        "ips": sorted(ips),
    }


def defang_text(text: str) -> str:
    def replace_url(match: re.Match[str]) -> str:
        value = match.group(0)
        trailing = value[len(value.rstrip(".,;)]}")):]
        value = value.rstrip(".,;)]}")
        value = re.sub(r"(?i)^https://", "hxxps://", value)
        value = re.sub(r"(?i)^http://", "hxxp://", value)
        return value.replace(".", "[.]") + trailing

    def replace_domain(match: re.Match[str]) -> str:
        value = match.group(0)
        suffix = value.rsplit(".", 1)[-1].split(":", 1)[0].lower()
        return value if suffix in NON_DOMAIN_SUFFIXES else value.replace(".", "[.]")

    def replace_ipv4(match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            return value
        return value.replace(".", "[.]")

    text = URL_PATTERN.sub(replace_url, text)
    text = DOMAIN_PATTERN.sub(replace_domain, text)
    text = IP_PATTERN.sub(replace_ipv4, text)
    return IPV6_PATTERN.sub(lambda match: match.group(0).replace(":", "[:]"), text)


def defang_report(report: Dict[str, Any]) -> Dict[str, Any]:
    safe_report = dict(report)
    for key in ("target_path", "command_line_arguments"):
        safe_report[key] = defang_text(report[key])
    safe_report["decoded_commands"] = [
        defang_text(command) for command in report["decoded_commands"]
    ]
    safe_report["indicators"] = {
        kind: [defang_text(value) for value in values]
        for kind, values in report["indicators"].items()
    }
    return safe_report


# Tüm bulguları bir araya getirerek JSON'a uygun analiz raporu oluşturur.
def analyze_lnk(lnk_path: Path) -> Dict[str, Any]:
    parsed = parse_lnk(lnk_path)
    target, arguments = extract_shortcut_fields(parsed)
    decoded_commands = decode_encoded_commands(arguments)
    combined_text = "\n".join([target, arguments, *decoded_commands])

    return {
        "file": str(lnk_path),
        "target_path": target,
        "command_line_arguments": arguments,
        "suspicious_tools": detect_suspicious_tools(combined_text),
        "decoded_commands": decoded_commands,
        "indicators": extract_indicators(combined_text),
    }


# Analiz raporunu renkli ve okunaklı bir terminal tablosunda gösterir.
def print_report(report: Dict[str, Any]) -> None:
    table = Table(title="PhishLnk-Inspector | LNK Analiz Özeti", show_lines=True)
    table.add_column("Alan", style="cyan", no_wrap=True)
    table.add_column("Bulgu", style="white", overflow="fold")

    table.add_row("Dosya", report["file"])
    table.add_row("Hedef yol", report["target_path"])
    table.add_row("Komut argümanları", report["command_line_arguments"] or "Yok")
    table.add_row("Şüpheli araçlar", ", ".join(report["suspicious_tools"]) or "Bulunmadı")
    table.add_row(
        "Decode edilen komutlar",
        "\n---\n".join(report["decoded_commands"]) or "Bulunmadı",
    )
    for kind, title in (("urls", "URL"), ("domains", "Alan adı"), ("ips", "IP")):
        table.add_row(title, ", ".join(report["indicators"][kind]) or "Bulunmadı")
    console.print(table)


# CLI argümanlarını işler ve analiz sonucunu terminale veya JSON'a yazar.
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Windows .lnk dosyalarını statik olarak analiz eder."
    )
    parser.add_argument("lnk_file", type=Path, help="Analiz edilecek .lnk dosyası")
    parser.add_argument(
        "--json", action="store_true", help="Bulguları JSON biçiminde yazdır"
    )
    parser.add_argument(
        "--no-defang",
        action="store_true",
        help="URL, alan adı ve IP adreslerini ham biçimde yazdır",
    )
    args = parser.parse_args(argv)

    if not args.lnk_file.is_file():
        parser.error(f"Dosya bulunamadı: {args.lnk_file}")
    if args.lnk_file.suffix.lower() != ".lnk":
        parser.error("Girdi dosyası .lnk uzantılı olmalıdır")

    try:
        report = analyze_lnk(args.lnk_file)
    except Exception as error:
        console.print(f"[bold red]LNK analiz edilemedi:[/] {error}", file=sys.stderr)
        return 1

    if not args.no_defang:
        report = defang_report(report)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
