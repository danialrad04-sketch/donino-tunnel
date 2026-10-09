# عملیات دو سرور

## نصب و ترتیب

طرح خارج اول نصب می‌شود و ایران بعد. هر node فقط بستهٔ تنظیمات و کلیدهای خود را می‌گیرد؛ کلید امضای CA و رمز پنل به خارج ارسال نمی‌شود. SSH host checking سخت‌گیرانه است و مقصد باید `user@host` باشد. پیش‌نیاز نصب root روی دو سرور است؛ سرویس‌ها با کاربر محدود اجرا می‌شوند. installer apt، ساخت کاربر و release جدید را انجام می‌دهد؛ روی سرویس‌های نامرتبط دست نمی‌گذارد.

تولید plan عملیات آفلاین است، نصب نیست. قبل از deploy فایل `plan.json` را بخوان. firewall میزبان و provider باید پورت‌های آن را اجازه دهند. برخی carriers به جهت خاص اتصال نیاز دارند. default FRP foreign→Iran است؛ BrowserLink/Paqet Iran→foreign هستند. سرویس مقصد باید loopback باشد.

## لایهٔ مشترک جریان

در مسیرهای FRP/BackPack/Backhaul/Paqet، دروازه به adapter محلیِ framed وصل می‌شود و engine دادهٔ قاب‌بندی‌شده را به adapter loopback خارج می‌رساند. این لایه EOF را داخل جریان منتقل می‌کند و تا پایان هر دو جهت سوکت حامل را باز نگه می‌دارد. قطع یک جهت در موتور زیرین قبلاً می‌توانست پاسخ بعد از upload EOF را کوتاه کند. اندازهٔ هر frame حداکثر ۳۲ KiB و header پنج بایت است؛ مقصدها ثابت، همهٔ listenerها loopback، ظرفیت هر adapter حداکثر ۱۰۲۴ ارتباط و idle timeout مشترک ۳۰۰ ثانیه است. این لایه رمزنگاری جدید ندارد؛ رمزنگاری و احراز هویت بر عهدهٔ carrier است. probe سلامت خودِ carrier و سرویس اصلی را می‌سنجد؛ خرابی adapter محلی هنگام باز کردن backend موجب fallback می‌شود.

## وضعیت

روی ایران:

```bash
/opt/donino-link/current/venv/bin/donino-link doctor --config /etc/donino-link/current/node.json
systemctl status donino-link.service donino-link-frp-wss-front.service donino-link-frp-quic.service
journalctl -u donino-link.service -n 100 --no-pager
journalctl -u donino-link-browser-wss.service -n 100 --no-pager
```

`doctor` برای هر مسیر جواب امضاشدهٔ تازه و وضعیت سرویس‌ها را چاپ می‌کند. deploy به حداقل یک مسیر سالم نیاز دارد؛ سالم نبودن مسیر دیگر به عنوان degraded گزارش می‌شود. باز بودن local TCP port به‌تنهایی سلامت محسوب نمی‌شود. تفاوت بین «تانل سالم» و «سرویس مقصد باز» در پاسخ وجود دارد. ابتدا مستقیم روی خارج سرویس مقصد را بررسی کن.

پنل به‌صورت پیش‌فرض روی ایران loopback:8090 است؛ با SSH port forwarding وارد شو، یا با [راهنمای پنل آنلاین](online-panel.md) HTTP عمومی را فعال کن. رمز اولیه هنگام plan تنظیم می‌شود و به صورت scrypt ذخیره می‌گردد. `admin.json` را برای تغییر رمز با `password_record` بازتولید کن و سرویس را restart کن. API token یک راز مستقل در `api-token` است؛ اشتراک‌گذاری آن دسترسی مدیریت می‌دهد. status/export کلیدها را برنمی‌گردانند.

`/api/metrics` با Bearer token قابل scrape است. token را در فایل دسترسی 600 ابزار مانیتورینگ قرار بده؛ در URL قرار نده. Prometheus شامل سلامت، زمان پاسخ، ارتباط‌ها و بایت‌های مسیر است. تاریخچهٔ نمودار ۱۲۰ probe در حافظه و audit حداکثر ۲۰۰۰ رویداد در SQLite است؛ نمودار packet loss واقعی نیست، شکست probe را نشان می‌دهد.

## رفتار قطع و کنترل

- prefer: مسیر ترجیحی برای اتصال جدید، همراه fallback هنگام ناسالم بودن.
- drain/disable: اتصال جدید روی آن مسیر باز نمی‌شود؛ اتصال موجود با فرمان مدیر قطع نمی‌شود.
- pause: هیچ اتصال جدیدی پذیرفته نمی‌شود؛ اتصال موجود ادامه می‌یابد.
- auto: ترجیح دستی برداشته می‌شود.

اگر خود carrier قطع شود، جریان جاریِ آن carrier قطع می‌شود. برنامهٔ سمت کاربر باید reconnect کند. retry فقط پیش از مصرف اولین بایت کاربر انجام می‌شود؛ تضمین مهاجرت نشست یا exactly-once کاربردی داده نمی‌شود. health probe هر ۳ ثانیه، آستانهٔ خرابی ۳ و بازیابی ۲ موفقیت است؛ زمان تشخیص ثابت ۳ ثانیه نیست.

## تمدید و rollback

گواهی leaf پس از ۹۰ روز منقضی می‌شود. پوشهٔ اصلی طرح و CA را آفلاین و محرمانه نگه دار:

```bash
donino-link renew --plan private-plan
donino-link deploy --plan private-plan --iran-host root@192.0.2.10 --foreign-host root@198.51.100.20
```

renew کلید leaf و pin مرورگر را عوض می‌کند، CA و tokenها را حفظ می‌کند. برای تمدید باید CA بیشتر از ۹۱ روز عمر باقی‌مانده داشته باشد؛ CA اولیه ۳۶۵روزه است. نزدیک انقضای CA یک طرح تازه و تعویض هماهنگ دو node لازم است. renew خودکار timer ندارد.

```bash
bash /opt/donino-link/current/scripts/rollback.sh
```

rollback واحدها و symlinkهای همین پروژه را به release قبلی برمی‌گرداند. apt packageها و user سیستم را حذف نمی‌کند. releaseها حاوی تنظیمات محرمانه‌اند؛ disk usage و چرخهٔ نگهداری را مدیریت کن. شکست اجرای installer همان node را برمی‌گرداند؛ شکست آزمون نهایی، nodeهای نصب‌شده را برمی‌گرداند. خاموش شدن کامل ماشین یا شکست rollback می‌تواند به بازیابی دستی نیاز داشته باشد.

## Paqet

Paqet تنها با `--experimental` و IPv4 عمومی واقعی. installer NIC، source IP و MAC دروازه را از route/neighbor کشف می‌کند؛ در صورت نبود اطلاعات توقف می‌کند. سه قانون iptables صرفاً برای peer و پورت اختصاصی و با tag `donino-link-paqet` اعمال می‌شوند؛ جدول‌ها flush نمی‌شوند. raw transport می‌تواند با فیلتر provider، NAT، policy مسیر و بسته‌های RST مشکل داشته باشد. آزمون local این پروژه raw packet end-to-end را تأیید نکرده است.

## BrowserLink

Debian و حداقل ۲ گیگ RAM برای ایران؛ `chromium` و `nodejs` از مخزن توزیع نصب می‌شوند. بسته‌ها SHA ثابت پروژه ندارند و تابع امنیت/به‌روزرسانی apt هستند. sandbox باید در کرنل و محیط systemd قابل اجرا باشد؛ اگر محیط user namespace یا IPC لازم را ممنوع کند، مسیر ناسالم می‌شود و FRP باقی می‌ماند. هیچ fallback تولیدی به `--no-sandbox` وجود ندارد. به‌روزرسانی browser ممکن است اثر انگشت و عملکرد را تغییر دهد؛ بعد از update، آزمون native اجرا شود.
