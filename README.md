# Donino Tunnel

مرکز مدیریت ارتباط دو سرور، با پنل فارسی، پایش واقعی مسیرها و نصب خودکار. نام بسته و دستور اجرایی `donino-link` است.

**نسخهٔ اولیهٔ قابل آزمایش است؛ تضمینِ غیرقابل تشخیص بودن، بی‌اختلال بودن یا سرعت ثابت ندارد.** آزمون واقعی شبکهٔ ایران و نصب روی VPS هنوز انجام نشده است. دروازهٔ انتخاب مسیر TCP است؛ UDP مستقیم از طریق Paqet و SOCKS5 آن قابل تنظیم است. QUIC نام حامل زیرین FRP است.

## آنچه ساخته شده

- **نسخهٔ ۰.۲.۰:** صفحهٔ مستقل برای هر بخش، موتور و سرویس؛ تب‌های سلامت، تنظیمات و لاگ زنده، تشخیص Paqet بیرونی، مشاهدهٔ نصب‌های دیگر و بازیابی Continuum از ورودی WSS جایگزین. [جزئیات نسخه و حدود سازگاری](docs/observability-v02.md).
- نصب ترمینالی یکسان روی هر دو سرور با انتخاب نقش، پنل HTTP مستقل ایران و خارج و جفت‌سازی خودکار SSH با کد یک‌بارمصرف؛ [راهنمای شروع](docs/role-setup.md).
- **تشخیص نصب موجود:** شناسایی خودکار سرویس‌های هر دو نقش، خواندن YAML/JSON بیرونی Paqet، journal زنده، مدیریت اختیاری، ویرایش با پشتیبان و rollback، و آزمون TCP/UDP از SOCKS5 موجود؛ اسکن هیچ حامل دیگری را فعال نمی‌کند. [راهنما](docs/existing-paqet.md).
- پنل مدرن فارسی RTL، مناسب موبایل، با حالت روشن/تیره و نمودار تأخیر، سلامت دو سرور، شمارندهٔ ترافیک، رویدادهای مدیر، انتخاب ترجیحی، تخلیه و توقف اتصال‌های جدید.
- آزمون سلامت تازه و امضاشده که از خودِ هر تانل عبور می‌کند؛ سلامت سرویس مقصد نیز جداگانه سنجیده می‌شود.
- انتخاب مستقل مسیر و تغییر مسیر اتصال‌های جدید هنگام خرابی. حامل‌های قبلی اتصال جاریِ قطع‌شده را مهاجرت نمی‌دهند؛ Continuum نشست خودش را در مهلت محدود روی WSS تازه بازیابی می‌کند.
- FRP روی WSS با ورودی mTLS و FRP روی QUIC؛ BackPack، Paqet، Backhaul و BrowserLink با انتخاب صریح آزمایشی.
- **مدیریت پیشرفتهٔ Paqet:** فوروارد TCP/UDP، SOCKS5، تمام حالت‌ها و بلوک‌های رمزنگاری KCP، FEC، smux، PCAP و شبکهٔ هر دو نقش؛ آزمون امضاشدهٔ UDP و ابزارهای مدیریت در هر دو پنل؛ [راهنما و محدودیت‌ها](docs/paqet.md) · [۱۲۷ آزمون و شواهد دو سرور](docs/evidence/paqet-panel-tests.json).
- لایهٔ مشترک انتقال محدود برای حفظ پایان مستقل آپلود/دانلود حتی روی موتورهایی که TCP half-close را نگه نمی‌دارند.
- تولید تنظیمات، کلیدهای مجزا، واحدهای systemd، دانلود نسخه‌های ثابت با SHA256، نصب دو سرور با SSH و بازگشت تنظیمات در صورت شکست.
- **Donino Continuum v2:** نشست TCP با بازیابی محدود پس از قطع WSS، شمارهٔ بایت، ACK و حذف تکرار، fencing نسل اتصال، حفظ FIN و پایش بازیابی در هر دو پنل؛ [قرارداد و نصب](docs/continuum.md) · [۱۱۳ آزمون و شواهد CI](docs/evidence/continuum-tests.json). QUIC و تعویض بین حامل‌ها مرحلهٔ بعد هستند.
- **Donino Mux v1:** پروتکل لایهٔ کاربردی اختصاصی آزمایشی روی WSS/mTLS، دو نشست پایدار، چند جریان با اعتبار بایت و فریم، پایان مستقل و نصب هر دو نقش؛ [قرارداد پروتکل و راه‌اندازی](docs/donino-mux.md) · [۸۹ تست و شواهد نصب واقعی دو node آزمایشی](docs/evidence/donino-mux-tests.json).
- **BrowserLink:** مرورگر واقعی Chromium در ایران، صفحهٔ HTTPS روی سرور خارج را باز می‌کند و جریان‌های TCP را با WebSocket بومی همان سایت منتقل می‌کند. [طراحی و محدودیت‌ها](docs/browserlink.md).

## هستهٔ تطبیقی آزمایشی

انتخاب حامل برای اتصال‌های جدید می‌تواند با هزینهٔ مبتنی بر تأخیر، نوسان، probe ناموفق، فشار drain و تعداد جریان زنده انجام شود. تنظیم از پنل ایران اختیاری است؛ اولویت ثابت پیش‌فرض و قابل بازگشت می‌ماند. این قابلیت پروتکل تازه یا تضمین تشخیص‌ناپذیری نیست. [تحقیق، طراحی، فعال‌سازی و محدودیت‌ها](docs/adaptive-core.md).

## پنل

تصویر زیر از آزمون محلی موتورهای واقعی است؛ اطلاعات شبکهٔ ایران نیست.

![پنل دسکتاپ](docs/evidence/panel-desktop.png)

[نمای موبایل](docs/evidence/panel-mobile.png) · [حالت تیره](docs/evidence/panel-dark.png) · [صفحهٔ ورود](docs/evidence/panel-login.png)

پنل مستقل خارج نیز روی دو node واقعی systemd آزمایش شده است: [نمای دسکتاپ خارج](docs/evidence/foreign-desktop.png) · [موبایل خارج](docs/evidence/foreign-mobile.png) · [حالت تیره](docs/evidence/foreign-dark.png) · [نبود شاهد تازه پس از لغو دسترسی](docs/evidence/foreign-unknown.png). تصاویر از شبکهٔ خصوصی آزمون هستند.

## راه‌اندازی از داخل پنل

پنل ایران اکنون اتصال SSH خارج، انتخاب هر هشت حامل، نقشهٔ نصب، آماده‌سازی هر دو node، فعال‌سازی مرحله‌ای، آزمون تمام مسیرها و بازگشت در شکست را مدیریت می‌کند. کاربر وب محدود است؛ سرویس نصب root جداگانه از socket محلی استفاده می‌کند. [راهنمای نصب از پنل](docs/panel-installer.md) · [تصویر فرم نصب](docs/evidence/iran-setup.png). اجازهٔ SSH با کد پنل خارج خودکار ثبت می‌شود؛ پورت‌های provider باید مجاز باشند. [نصب دو پنل از ترمینال](docs/role-setup.md).

## نصب

کنترل‌کننده: Linux/macOS با Python 3.10+، OpenSSL و SSH. سرورها: Debian 12/13 یا Ubuntu 22.04 تا 26.04 با systemd، amd64/arm64. مسیر مرورگری روی اوبونتو با Chromium مستقل از Snap نصب می‌شود؛ sandbox باید در کرنل میزبان قابل اجرا باشد.

نصب با یک فرمان؛ در ترمینال **هر سرور با کاربر root** اجرا کن:

```bash
curl -fL --retry 3 https://raw.githubusercontent.com/danialrad04-sketch/donino-tunnel/main/install-donino.sh -o install-donino.sh && bash install-donino.sh
```

`1` را برای ایران و `2` را برای خارج انتخاب کن؛ آدرس همین سرور و رمز مدیر را وارد کن. پنل و سرویس مدیریت هر نقش خودکار نصب، اجرا و برای روشن‌شدن پس از ریبوت فعال می‌شوند. در پایان لینک پنل چاپ می‌شود. اگر نصب قبلی وجود داشته باشد، گزینهٔ ارتقا با حفظ نقش، رمز، پورت و تنظیمات نشان داده می‌شود. پیش‌نیاز دریافت فایل `curl` است؛ نصب وابستگی‌های برنامه خودکار انجام می‌شود.

روش دریافت دستی: [فایل مستقل install-donino.sh](install-donino.sh) را دانلود و روی هر دو سرور کپی کن، سپس:

```bash
sudo bash install-donino.sh
```

فقط همین فایل لازم است؛ سورس برنامه همراه آن است. [راهنمای کامل نصب و ارتقا](docs/role-setup.md).

برای **به‌روزرسانی نصب موجود**، ابتدا روی خارج و سپس روی ایران اجرا کن:

```bash
curl -fL --retry 3 --connect-timeout 15 https://raw.githubusercontent.com/danialrad04-sketch/donino-tunnel/main/install-donino.sh -o install-donino.sh && bash install-donino.sh --upgrade
```

نقش، رمز، پورت و تنظیمات فعلی حفظ می‌شوند. سرویس‌های مدیریت‌شدهٔ Donino هنگام ارتقا از نو شروع می‌شوند؛ Paqet و دیگر نصب‌های مستقل توسط اسکن تغییر یا restart نمی‌شوند. پس از ارتقای هر دو طرف، صفحهٔ پنل را دوباره بارگذاری کن. نسخهٔ نصب‌شده:

```bash
/opt/donino-link/current/venv/bin/python -c 'from donino_link import __version__; print(__version__)'
```

روش جایگزین با سورس مخزن:

```bash
git clone https://github.com/danialrad04-sketch/donino-tunnel.git
cd donino-tunnel
sudo bash scripts/setup.sh
```

اسکریپت را **روی هر دو سرور** اجرا کن؛ `1` ایران و `2` خارج. پنل‌ها پیش‌فرض روی HTTP پورت‌های `8090` و `8091` بالا می‌آیند. در خارج کد جفت‌سازی بساز و در ایران وارد کن؛ نصب حامل‌ها از پنل ایران انجام می‌شود. [جزئیات و ارتقا](docs/role-setup.md).

روش جایگزین CLI برای ساخت plan روی کنترل‌کننده:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
donino-link plan --iran 192.0.2.10 --foreign 198.51.100.20 \
  --service app=0.0.0.0:443,127.0.0.1:8443 \
  --transport frp-wss --transport frp-quic --output private-plan
```

IPهای مثال را عوض کن. سرویس اصلی باید روی **loopback سرور خارج، پورت 8443** اجرا شود. رمز پنل تعاملی دریافت می‌شود. کل پوشهٔ plan محرمانه است و نباید commit شود.

ابتدا fingerprint کلید SSH هر دو سرور را از مسیر قابل اعتماد بررسی و در known_hosts ثبت کن. پورت‌های `private-plan/plan.json` را در فایروال میزبان و شرکت میزبان باز کن. نصب‌کننده فایروال عمومی را باز یا پاک نمی‌کند.

```bash
donino-link deploy --plan private-plan --iran-host root@192.0.2.10 \
  --foreign-host root@198.51.100.20 --identity ~/.ssh/id_ed25519 --dry-run
donino-link deploy --plan private-plan --iran-host root@192.0.2.10 \
  --foreign-host root@198.51.100.20 --identity ~/.ssh/id_ed25519
ssh -N -L 8090:127.0.0.1:8090 root@192.0.2.10
```

پنل: `http://127.0.0.1:8090`. دسترسی عمومی با HTTP هم با انتخاب صریح `--http` پشتیبانی می‌شود؛ پیش‌فرض loopback است. [راه‌اندازی پنل آنلاین](docs/online-panel.md). جزئیات نگهداری و خطایابی در [راهنما](docs/operations.md).

برای سه مسیر، با مرورگر واقعی:

```bash
donino-link plan --iran 192.0.2.10 --foreign outside.example.com \
  --service app=0.0.0.0:443,127.0.0.1:8443 \
  --transport frp-wss --transport frp-quic --transport browser-wss \
  --experimental --browser-port 443 --output private-browser-plan
```

در این مثال، دامنهٔ `outside.example.com` متعلق به تو و به سرور خارج اشاره می‌کند. SSH سرور خارج می‌تواند IP همان سرور باشد. مسیر BrowserLink به خارج اتصال می‌زند؛ دو مسیر FRP از خارج به ایران اتصال معکوس دارند. برای BrowserLink سرور ایران حداقل ۲ گیگابایت RAM در نظر بگیر؛ ظرفیت واقعی را با بار کاری خودت اندازه بگیر.

## شواهد و پژوهش

[پژوهش ۲۶ خانوادهٔ روش](docs/research.md) · [طراحی BrowserLink](docs/browserlink.md) · [عملیات](docs/operations.md) · [وضعیت اعتبارسنجی](docs/validation.md)

```bash
python -m unittest discover -s tests -v
python scripts/test-engines.py
python scripts/test-browser.py --chromium /usr/bin/chromium --output browser-results.json
```

آزمون مرورگر باید در محیطی اجرا شود که IPC داخلی Chromium مجاز باشد. آزمون واحد جایگزین آزمون مرورگر واقعی نیست. [GitHub Actions](https://github.com/danialrad04-sketch/donino-tunnel/actions) ماتریس واحد، موتورهای واقعی، مرورگر، رابط پنل و نصب دو node با systemd را اجرا می‌کند.

کد خود پروژه MIT است. موتورهای دانلودشده و فونت مجوز مستقل دارند؛ [مجوزها](docs/research.md#licenses) را ببین.


## Continuum v2 — بازیابی نشست آزمایشی

نسخهٔ فعلی این حامل WSS → WSS را پیاده می‌کند. برای استفاده، فایل نصب جدید را روی هر دو نقش با `--upgrade` اجرا و در پنل ایران `donino-continuum` را با اجازهٔ آزمایشی نصب کن. هنگام استفاده از چند حامل، این مسیر را ترجیح بده. سوکت مقصد فقط تا زمانی که پردازش و نشست زنده‌اند نگه‌داری می‌شود؛ restart سرور خارج یا پایان مهلت جریان را می‌بندد. [محدودیت‌ها، قرارداد و مراحل بعد](docs/continuum.md).

۱۱۳ آزمون روی Python 3.11/3.12/3.13 و هر هفت job اجرای CI نسخهٔ Continuum موفق شدند؛ دو node آزمایشی با نصب هر هشت حامل، بازیابی سه قطع واقعی سوکت هنگام آپلود، دو پنل و rollback بررسی شدند. این شواهد، تست شبکهٔ ایران یا DPI نیستند. [شاهد commit و اجرای CI](docs/evidence/continuum-tests.json).
