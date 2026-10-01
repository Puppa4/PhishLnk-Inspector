# PhishLnk-Inspector

Windows `.lnk` kısayollarını çalıştırmadan statik olarak inceleyen hafif bir Blue Team / SOC CLI aracıdır. `LnkParse3` ile kısayol verisini okur; yaygın LOLBAS araçlarını, PowerShell Base64 komutlarını, URL'leri, alan adlarını ve IPv4/IPv6 adreslerini raporlar.

## Kurulum

Python 3.9 veya üzeri gerekir.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Kullanım

Komutlarda `C:\path\to\file.lnk` bölümünü analiz etmek istediğiniz `.lnk` dosyasının yolu ile değiştirin. `.lnk` örnekleri `.gitignore` tarafından GitHub'a eklenmediği için bu depoda örnek dosya bulunmayabilir.

```powershell
python main.py "C:\path\to\file.lnk"
python main.py "C:\path\to\file.lnk" --json
python main.py "C:\path\to\file.lnk" --no-defang
```

`PhishLnk-Inspector.py` aynı CLI için alternatif giriş noktasıdır.

URL'ler, alan adları ve IP adresleri terminal ve JSON raporlarında varsayılan olarak defang edilir. Ham değerler için `--no-defang` kullanın.

Analiz statiktir; LNK içindeki komutlar çalıştırılmaz. Arşivlerden (`.zip`, `.iso`) otomatik çıkarma bu başlangıç sürümünün kapsamı dışındadır. Alan adı ve IP eşleşmeleri regex ile aday olarak bulunur; sonuçlar analist tarafından doğrulanmalıdır.
