# PhishLnk-Inspector

Windows `.lnk` kısayollarını çalıştırmadan statik olarak inceleyen hafif bir Blue Team / SOC CLI aracıdır. `LnkParse3` ile kısayol verisini okur; yaygın LOLBAS araçlarını, PowerShell Base64 komutlarını, URL'leri, alan adlarını ve IPv4 adreslerini raporlar.

## Kurulum

Python 3.9 veya üzeri gerekir.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Kullanım

```powershell
python main.py .\samples\suspicious.lnk
python main.py .\samples\suspicious.lnk --json
```

Analiz statiktir; LNK içindeki komutlar çalıştırılmaz. Arşivlerden (`.zip`, `.iso`) otomatik çıkarma bu başlangıç sürümünün kapsamı dışındadır. Alan adı ve IP eşleşmeleri regex ile aday olarak bulunur; sonuçlar analist tarafından doğrulanmalıdır.
