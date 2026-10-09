# وضعیت اعتبارسنجی

دامنهٔ شواهد: Linux amd64، loopback محلی و runnerهای GitHub Actions. هیچ نتیجه‌ای از مسیر واقعی ایران↔خارج، raw Paqet در WAN، بار ۲۴ساعته، مصرف CPU/RSS تحت بار ۳۲ جریان یا نصب واقعی با systemd روی دو VPS به دست نیامده است. این تمایز بخشی از تعریف نسخه است.

## آزمون واحد و امنیت

۳۶ تست شامل اعتبارسنجی endpoint و تنظیمات، امضای تازهٔ probe، رد listener جعلی، hysteresis، fallback قبل از مصرف داده، حفظ half-close، drain، حالت پایدار مدیر، ورود و CSRF و Origin و خروج، rate limit، عدم افشای راز، metrics، قوانین raw scoped، SSH injection، جداسازی کلیدهای node، تولید و تمدید گواهی/pin، پورت 443 مستقل روی دو node، مرز frame، لایهٔ مشترک انتقال، انتخاب صریح HTTP عمومی، رد برخورد پورت و حفظ دسترسی فایل تنظیمات است. ماتریس CI با Python 3.11، 3.12 و 3.13 اجرا می‌شود.

## موتورهای واقعی

نسخه‌های ثابت در manifest دانلود، SHA256 بررسی و برنامه‌های اصلی اجرا شدند: FRP WSS، FRP QUIC، BackPack WSS و Backhaul WSS. در هر مسیر ۲ MiB upload و ۲ MiB پاسخ، با تطابق SHA256 و پاسخ بعد از EOF آپلود بررسی می‌شود. mTLS نبودِ گواهی client را رد می‌کند. FRP WSS عمداً قطع می‌شود و ۵۱۲ KiB اتصال جدید از QUIC می‌گذرد. [خروجی محلی](evidence/local-engine-tests.json).

Paqet فقط به لحاظ ساخت config، cipher موجود در source و قواعد محدود iptables بررسی شده؛ عنوان pass end-to-end برای آن نداریم. Backhaul آزمایشی با محدودیت شناخته‌شدهٔ server authentication است، حتی اگر payload loopback آن صحیح منتقل شود.

## مرورگر واقعی

آزمون native با Google Chrome 154 روی GitHub runner، با sandbox فعال، اجرا می‌شود. دو جریان هم‌زمان ۴ و ۲ MiB در هر جهت، محتوای تصادفی و صحت کامل، پاسخ پس از پایان upload، رد cookie/Origin/مقصد نامعتبر، probe امضاشده و قطع process و بازیابی مرورگر بررسی می‌شود. آزمون توسعه‌یافته دروازهٔ واقعی را هم به مرورگر و FRP QUIC وصل می‌کند و پس از توقف مرورگر انتخاب QUIC، سپس بازگشت مرورگر را بررسی می‌کند.

نتایج زمان‌گیری فقط مدت یک echo دوطرفه روی loopback است؛ benchmark پهنای باند WAN، تضمین upload یا نشان‌دهندهٔ مقاومت در برابر DPI نیست. ظرفیت ۳۲ جریان سقف تنظیمات است، نه ظرفیت اثبات‌شدهٔ benchmark. فایل [نتیجهٔ native](evidence/native-browser-tests.json) commit و workflow شاهد را مشخص می‌کند.

محیط محلی ChatGPT اجازهٔ IPC لازم برای Chromium را نداد؛ آزمون native در GitHub Actions انجام شد. نتیجهٔ آزمون‌های سرور Python به جای native گزارش نشده است.

## پنل واقعی

Playwright روی پنلِ متصل به چهار موتور واقعی تست ورود، توقف/ادامه، prefer، به‌روزرسانی دستی، ماندگاری تم روشن/تیره بعد از reload و خروج موبایل را انجام می‌دهد. viewport دسکتاپ 1440×1000 و موبایل 390×844؛ خطای JavaScript و overflow افقی بررسی می‌شود. تصاویر [دسکتاپ](evidence/panel-desktop.png) و [موبایل](evidence/panel-mobile.png) از fixture محلی روی runner هستند، نه سرورهای واقعی ایران و خارج. تصویر بعد از قطع عمدی مسیر WSS گرفته شد؛ قرمز بودن آن مسیر انتظار آزمون است. تصاویر بازبینی بصری شدند؛ پنل جدید در هر دو تم و موبایل خوانا و بدون overflow است. [حالت تیره](evidence/panel-dark.png)، [صفحهٔ ورود](evidence/panel-login.png) و [نتیجهٔ آزمون](evidence/panel-ui-tests.json). HTTP عمومی با انتخاب صریح آماده است؛ استقرار واقعی روی VPS هنوز انجام نشده است.

## پذیرش شبکهٔ واقعی

قبل از استفادهٔ جدی، دو سرور با ساعت صحیح، پورت‌های provider باز، سرویس واقعی loopback، SSH معتبر و دامنه/گواهی مناسب لازم‌اند. installer با dry-run و بسته‌بندی تست شده اما نصب واقعی و rollback واقعی systemd هنوز نیازمند VPS است. پس از نصب، health و app payload جدا بررسی، سپس soak test و reconnect هنگام تغییر مسیر انجام شود. packet loss، شکست handshake، p95 latency، upload/download، مصرف منابع و زمان بازیابی ثبت شوند. IP/دامنه یا uplink مشترک ممکن است همهٔ carrierها را هم‌زمان از دسترس خارج کند.
