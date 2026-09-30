# /// script
# requires-python = ">=3.9"
# dependencies = ["LnkParse3>=1.6.0", "rich>=13.7"]
# ///

# Bu dosya, kısa proje adıyla CLI'yi çalıştırmak için uyumluluk giriş noktasıdır.
from main import main


if __name__ == "__main__":
    raise SystemExit(main())
