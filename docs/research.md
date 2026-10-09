# پژوهش روش‌ها — ۲۰۲۶-۱۰-۰۹

این یک بررسی هدفمندِ ۲۶ خانواده است، نه ادعای مطالعهٔ همهٔ مخازن اینترنت. README/مستندات اولیهٔ خانواده‌ها بررسی شدند. برای FRP، BackPack، Backhaul و Paqet علاوه بر مستندات، config و کد شبکه/امنیت نسخهٔ ثابت بررسی شد. چهار carrier با binary واقعی در Linux loopback آزمون شدند؛ آزمون تکمیلی systemd هر شش carrier، شامل Paqet raw و مرورگر، را با ۲ MiB در هر جهت روی Docker bridge بررسی کرد. Paqet در WAN واقعی آزمایش نشده است.

| خانواده و منبع اولیه | کاربرد/ویژگی | تصمیم این نسخه |
|---|---|---|
| [FRP](https://github.com/fatedier/frp) | reverse TCP؛ حامل WSS/QUIC | دو مسیر پیش‌فرض؛ mTLS front برای WSS |
| [BackPack](https://github.com/AminMGMT/BackPack) | reverse multiplexed tunnel | انتخاب آزمایشی؛ upstream/version در manifest مرجع قطعی است |
| [Backhaul](https://github.com/Musixal/Backhaul) | reverse TCP/WSS | legacy آزمایشی؛ اعتبارسنجی TLS در dialer نسخهٔ بررسی‌شده ضعیف است |
| [Paqet](https://github.com/hanselime/paqet) | raw TCP/pcap و KCP | آزمایشی؛ نیازمند NIC/MAC و قوانین scoped |
| [rathole](https://github.com/rathole-org/rathole) | reverse proxy سبک | پژوهش؛ adapter پیاده نشده |
| [GOST](https://github.com/go-gost/gost) | زنجیرهٔ پروکسی و حامل‌های متنوع | پژوهش؛ پیچیدگی ترکیب و config بیشتر |
| [wstunnel](https://github.com/erebe/wstunnel) | WebSocket/HTTP tunnel | پژوهش؛ گزینهٔ استاندارد بدون browser runtime |
| [Chisel](https://github.com/jpillora/chisel) | TCP over HTTP با SSH | پژوهش؛ framing مخصوص و هزینهٔ encapsulation |
| [Hysteria](https://github.com/apernet/hysteria) | QUIC و congestion control اختصاصی | پژوهش؛ UDP باید در مسیر عملی قابل استفاده باشد |
| [kcptun](https://github.com/xtaci/kcptun) | KCP روی UDP | پژوهش؛ tuning و loss/FEC هزینه دارند |
| [udp2raw](https://github.com/wangyu-/udp2raw) | بسته‌بندی UDP در fakeTCP/ICMP | پژوهش؛ raw و policy فایروال حساس |
| [WireGuard](https://www.wireguard.com/protocol/) | VPN سریع UDP | پژوهش؛ پروتکل قابل شناسایی و UDP وابسته به مسیر |
| [OpenVPN](https://github.com/OpenVPN/openvpn) | VPN TLS روی UDP/TCP | پژوهش؛ TCP nesting و fingerprint نیازمند توجه |
| [strongSwan/IPsec](https://docs.strongswan.org/) | IKE/IPsec | پژوهش؛ پور‌ت‌ها و negotiation مشخص |
| [SoftEther](https://github.com/SoftEtherVPN/SoftEtherVPN) | VPN SSL و چند پروتکل | پژوهش؛ سنگین‌تر از service gateway |
| [OpenSSH](https://www.openssh.com/manual.html) | local/reverse forwarding | پژوهش؛ مدیریت ساده، handshake SSH مشخص |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) | relay مدیریت‌شده به شبکهٔ شرکت | پژوهش؛ به provider و policy آن وابسته |
| [Tailscale](https://github.com/tailscale/tailscale) | overlay WireGuard و DERP | پژوهش؛ هماهنگی/relay خارجی |
| [ZeroTier](https://github.com/zerotier/ZeroTierOne) | overlay شبکه | پژوهش؛ کنترل‌پلین و UDP/relay |
| [n2n](https://github.com/ntop/n2n) | overlay peer/supernode | پژوهش؛ نیازمند تنظیم و شبکهٔ مناسب |
| [Cloak](https://github.com/cbeuw/Cloak) | پوشش transport | پژوهش؛ هیچ پوششی مصونیت عمومی اثبات نمی‌کند |
| [Xray](https://github.com/XTLS/Xray-core) / [sing-box](https://github.com/SagerNet/sing-box) | transport/proxy و TLS متعدد | پژوهش؛ نیازمند configuration و سنجش مستقل |
| [Shadowsocks](https://github.com/shadowsocks/shadowsocks-rust) | پروکسی رمز‌شده | پژوهش؛ encryption به‌تنهایی camouflage نیست |
| [GRE/IPIP/SIT](https://man7.org/linux/man-pages/man8/ip-tunnel.8.html) | encapsulation شبکهٔ kernel | پژوهش؛ رمزنگاری ذاتی و پوشش وب ندارند |
| [VXLAN/GUE](https://www.kernel.org/doc/Documentation/networking/vxlan.txt) | encapsulation لایهٔ شبکه روی UDP | پژوهش؛ مناسب شبکهٔ قابل کنترل، نه تضمین عبور DPI |
| [iodine](https://github.com/yarrick/iodine) / [sslh](https://github.com/yrutschle/sslh) | DNS tunnel / تقسیم پروتکل روی پورت | پژوهش؛ iodine کم‌ظرفیت، sslh خودِ carrier نیست |

## بررسی عمیقِ نسخه‌ها

مرجع URL، version، asset و SHA256 واقعی در [`engines.json`](../donino_link/engines.json) است؛ دانلود latest در installer انجام نمی‌شود. نسخه‌های بررسی‌شده FRP 0.71.0، BackPack 1.8.5، Backhaul 0.7.2 و Paqet 1.0.0-alpha.21 هستند.

FRP WSS به صورت public mTLS front→loopback FRPS websocket اجرا می‌شود. قرار دادن `transport.tls.trustedCaFile` در FRPS داخلی باعث اجبار TLS داخلی می‌شد؛ config سازنده آن را حذف می‌کند و outer front کلاینت با گواهی معتبر را الزام می‌کند. QUIC با CA و client certificate تنظیم شده است. آزمون واقعیِ نبود client certificate و انتقال payload برای WSS موفق بود.

BackPack در config این پروژه `simple_auth=false` و `skip_optz=true` دارد. کد TLS-exporter/HMAC نسخهٔ بررسی‌شده binding دارد ولی fallback سازگاری در بررسی proof سمت سرور مشاهده شد؛ بنابراین پیش‌فرض پروژه نیست. Backhaul WSS در `internal/utils/network/ws_dialer.go` با `InsecureSkipVerify` دیده شد و token در handshake ارائه می‌شود؛ این مسیر تضمین server authentication در برابر MITM ندارد و تنها انتخاب legacy آزمایشی است. قرار دادن آن روی اینترنت بدون ارزیابی مستقل توصیهٔ پیش‌فرض نیست.

Paqet با AES-128-GCM که در factory رمزنگاری نسخهٔ ثابت موجود است تنظیم شده؛ KCP mode=normal، MTU=1150 و conn=2 آغاز محافظه‌کارانه‌اند و بهترین تنظیم جهانی نیستند. raw packet نیازمند آزمون واقعیِ route و پورت غیرمعمول است. cipher یا checksum به‌تنهایی loss/فیلترینگ را حل نمی‌کند.

## چرا چند مسیر مستقل

carrierها داخل یکدیگر انباشته نشده‌اند. هر مسیر health probe خود را دارد و سرویس‌های جدید به مسیر سالم با اولویت تنظیم‌شده می‌روند. الگوریتم بیشترین سرعت را از latency استنتاج نمی‌کند: اولویت عملیاتی، سلامت سرویس، latency و بار سنجیده‌شده است. همهٔ مسیرها می‌توانند از یک IP و uplink عبور کنند؛ مسدود شدن IP/دامنه، خرابی provider یا قطع سراسری ممکن است همه را هم‌زمان از کار بیندازد. این پروژه چند سرور خروج یا توزیع providerها را هنوز خودکار نمی‌کند.

BrowserLink یک adapter مستقل به این طراحی اضافه می‌کند. مرورگر واقعی برخی تفاوت‌های پشتهٔ client را کم می‌کند، اما حجم، زمان‌بندی، مقصد و طول نشست باقی‌اند. تمرکز نسخهٔ فعلی انتقال صحیح، auth، جریان محدود و fallback قابل مشاهده است؛ وعدهٔ شکست‌ناپذیری وجود ندارد.

## Licenses

کد Donino Tunnel با MIT منتشر شده. موتورهای upstream با مجوز خودشان استفاده می‌شوند و binary آنها در سورس این مخزن کپی نشده است: FRP Apache-2.0؛ BackPack AGPL-3.0؛ Backhaul AGPL-3.0؛ Paqet MIT. قبل از توزیع ترکیبی یا تغییر upstream، LICENSE همان tag در URL manifest بررسی شود. فونت محلی Vazirmatn با OFL و متن مجوز همراه است. Chromium و Node وابستگی‌های سیستم‌اند و مجوزهای مستقل دارند. این پروژه کد cryptography موتورهای upstream را کپی نکرده است.
