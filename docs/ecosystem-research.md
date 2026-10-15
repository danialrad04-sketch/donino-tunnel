# منابع معماری و مجوزهای Network Studio

بررسی در ۲۰۲۶-۱۰-۱۵ از مخازن اصلی انجام شد. لینک‌های Google ارسالی به این منابع اصلی تبدیل شدند. پژوهش فهرست کامل تمام نرم‌افزارهای تانلینگ GitHub نیست؛ افزونهٔ هر ابزار باید قرارداد، نصب، سلامت، محدودیت و آزمون مستقل داشته باشد.

| منبع | نسخه/commit بررسی‌شده | نتیجهٔ طراحی |
| --- | --- | --- |
| [3x-ui](https://github.com/MHSanaei/3x-ui/tree/v3.10.2) | `608ef4e4010bf83e2e78328e08f77efc051ad4d7`؛ v3.10.2 | پنل Go، API scoped token، Xray، مدل مستقل clients و attachment به inbound؛ read/write model متفاوت |
| [3x-ui قدیمی](https://github.com/MHSanaei/3x-ui/tree/v2.8.11) | `52fdf5d4296b4534e25d6221d82ec7d819a9b952` | client در settings inbound، cookie login و API متفاوت؛ آداپتر جدا |
| [PasarGuard/panel](https://github.com/PasarGuard/panel/tree/v5.4.1) | `b56ffe369f542152c52c69733205baeaf3f6e4cd` | پنل Python، کاربران/گروه‌ها/نودها، API با Bearer یا ApiKey؛ backend صاحب سهمیه و اشتراک می‌ماند |
| [PasarGuard/node](https://github.com/PasarGuard/node/tree/e9a9ba286413c404854b80c847b588b620426660) | `e9a9ba286413c404854b80c847b588b620426660` | عامل node است؛ جایگزین API پنل مدیریتی نیست |
| [Xray-core](https://github.com/XTLS/Xray-core) | باینری همراه توزیع 3x-ui v3.10.2، در آزمون `26.10.10` | هستهٔ داده، جدا از control plane و carrier؛ رفتار freedom جدید برای loopback در آزمون لحاظ شده |

مرجع قرارداد 3x-ui: `internal/web/controller/{api,client,inbound,server}.go` و `internal/database/model/model.go`. مدل v3 در پاسخ `ClientRecord` با `uuid` دارد؛ API نوشتن `Client` با `id` می‌گیرد. مرجع PasarGuard: `app/routers/{user,system,node,authentication}.py` و `app/models/user.py`. توکن API Key باید با `Authorization: ApiKey …` یا `X-Api-Key` برود؛ Access Token با Bearer می‌رود.

رابط Donino از پایه با همان دارایی‌های محلی خودش نوشته شد. کد UI، server، crypto یا migration پنل‌های مرجع وارد بستهٔ Python نشده است. برای نصب اختیاری backend، توزیع باینری اصلی از URL ثابت upstream دریافت می‌شود، SHA256 آن بررسی می‌شود، و shell installer upstream اجرا نمی‌شود. source همان نسخه از لینک بالا در دسترس است؛ متن GPL در نصب همراه است. اگر upstream را تغییر می‌دهی یا محصول ترکیبی را توزیع می‌کنی، تعهدات مجوز همان اجزا باید رعایت شوند.

| جزء مستقل | مجوز upstream |
| --- | --- |
| Donino | MIT |
| 3x-ui؛ PasarGuard/node | GPL-3.0 |
| PasarGuard/panel | AGPL-3.0 |
| Xray-core | MPL-2.0 |
| FRP؛ Rathole | Apache-2.0 |
| BackPack؛ Backhaul | AGPL-3.0 |
| Paqet؛ GOST؛ Chisel؛ Hysteria | MIT |
| sing-box؛ TUIC | GPL-3.0 |
| WireGuard kernel implementation | GPL-2.0 |

مجوزها از فایل و metadata مخزن اصلی بررسی شدند؛ اجزای جانبی هر توزیع ممکن است مجوزهای جدا داشته باشند. کاتالوگ قابلیت‌ها مجوز نصب خودکار یا شاهد صحت یک ابزار صرفاً بر اساس حضور آن در GitHub نیست. طرح توسعهٔ آداپتر باید حداقل اعتبارسنجی config، manifest ثابت، health probe معتبر، lifecycle، rollback، مرز اسرار و آزمون باینری واقعی داشته باشد.
