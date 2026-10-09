# پنل آنلاین Donino Tunnel

پنل واقعی روی سرور ایران اجرا می‌شود و در مرورگر موبایل و دسکتاپ قابل مدیریت است. ظاهر جدید: منوی مستقل، رنگ بنفش روشن، حالت تیرهٔ نفتی، یادآوری تم، کارت مسیرها، سلامت زنده، نرخ ترافیک مجموع دو جهت، نشانگر حافظه و رویدادهای خوانا. شمارنده‌ها و نمودار از API واقعی می‌آیند؛ دادهٔ نمونه روی پنل تولیدی نوشته نشده است.

## روی سرورِ نصب‌شده

ابتدا نسخهٔ جدید پروژه باید روی node نصب شود؛ صرف clone کردن سورس، بستهٔ جاری systemd را به‌روز نمی‌کند. برای حفظ کلیدها، رمز و تنظیمات، همان plan خصوصی خودت را با نسخهٔ جدید ابزار deploy کن. سپس روی ایران، از checkout جدید مخزن:

```bash
sudo bash scripts/expose-panel.sh --http --host YOUR_IRAN_IP --port 8090
```

این helper تنظیمات قبلی و رمز را حفظ می‌کند، فایل backup خصوصی می‌سازد، مالکیت و دسترسی فایل node را نگه می‌دارد، HTTP عمومی را فعال و سرویس موجود را restart می‌کند. برای استفاده در مرورگر، IP واقعی سرور را به جای `YOUR_IRAN_IP` بگذار. لینک واقعی بعد از اجرای موفق روی سرور چاپ می‌شود. اگر برنامه هنوز روی دو VPS نصب نشده، ابتدا راهنمای README و deploy دو node را اجرا کن؛ helper نصب‌نشده را آنلاین جا نمی‌زند.

فایروال میزبان و شرکت میزبان باید inbound TCP 8090 را اجازه دهند. helper آنها را خودکار تغییر نمی‌دهد. اگر UFW فعال است، روی همان سرور:

```bash
sudo ufw allow 8090/tcp comment 'Donino admin panel'
```

آدرس مرورگر `http://YOUR_IRAN_IP:8090` است. رمز همان رمز مدیرِ زمان تولید plan است. HTTP رمز و cookie نشست را در مسیر شبکه رمزنگاری نمی‌کند؛ رمز ورود، HttpOnly/SameSite cookie، CSRF، Origin check و محدودیت تلاش ورود همچنان فعال‌اند.

## تنظیم مستقیم

```bash
sudo /opt/donino-link/current/venv/bin/donino-link panel-access \
  --config /etc/donino-link/current/node.json \
  --listen 0.0.0.0:8090 --http --public-host YOUR_IRAN_IP
sudo systemctl restart donino-link.service
```

تنظیم JSON معتبر برای HTTP عمومی:

```json
{
  "listen": "0.0.0.0:8090",
  "allow_insecure_http": true,
  "credentials_file": "/etc/donino-link/current/admin.json",
  "api_token_file": "/etc/donino-link/current/api-token"
}
```

این قسمت داخل `panel` فایل node قرار می‌گیرد؛ جایگزین کل node.json نیست. بدون انتخاب صریح HTTP، listener عمومی همچنان TLS می‌خواهد. پورت تکراری با ورودی کاربر یا backend رد می‌شود. وب API حق تغییر listener، باز کردن فایروال یا اجرای shell ندارد.

برای بازگشت به دسترسی محلی:

```bash
sudo /opt/donino-link/current/venv/bin/donino-link panel-access \
  --config /etc/donino-link/current/node.json --listen 127.0.0.1:8090
sudo systemctl restart donino-link.service
```

## بررسی دسترسی

```bash
sudo systemctl status donino-link.service
sudo ss -lntp '( sport = :8090 )'
```

باید listener روی `0.0.0.0:8090` وجود داشته باشد. `healthz` فقط زنده بودن سرویس را نشان می‌دهد، نه سلامت تانل. سلامت مسیرها بعد از ورود قابل مشاهده است. اگر healthz محلی جواب می‌دهد ولی مرورگر بیرونی وصل نمی‌شود، NAT، firewall میزبان یا firewall شرکت میزبان را بررسی کن. راه‌اندازی عمومی تنها پس از اجرای این تنظیمات روی VPS و آزمون از بیرون، آنلاین محسوب می‌شود.
