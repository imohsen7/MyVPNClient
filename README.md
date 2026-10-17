# L2TP VPN Client Android 7+ (API 24+) Project

پروژه کامل اپلیکیشن اندروید برای اتصال به L2TP/IPSec VPN با پشتیبانی از حداقل اندروید ۷٫۰ (API 24) و تمامی نسخه‌های بالاتر.

## روش‌های ساخت فایل APK نهایی:

### روش ۱: ساخت خودکار APK با GitHub Actions (رایگان و بدون نیاز به کامپیوتر یا اندروید استودیو)
1. این فایل‌ها را در یک ریپازیتوری جدید در گیت‌هاب (GitHub) آپلود کنید.
2. به تب **Actions** در گیت‌هاب بروید؛ فرآیند `Build Android APK` به صورت خودکار اجرا می‌شود.
3. پس از حدود ۲ دقیقه، فایل نهایی `app-release.apk` در بخش Artifacts آماده دانلود خواهد بود!

### روش ۲: کامپایل با Android Studio
1. برنامه **Android Studio** را باز کنید.
2. گزینه **Open** را انتخاب کرده و این پوشه را انتخاب نمایید.
3. از منوی بالا روی **Build > Build Bundle(s) / APK(s) > Build APK(s)** کلیک کنید.
4. فایل APK در مسیر `app/build/outputs/apk/debug/app-debug.apk` آماده نصب روی گوشی است.

### تنظیمات سرور از پیش ذخیره شده:
- Server: de-fra1.l2tp-vpn.net
- Pre-Shared Key (PSK): vpnsecret2026
- Username: vpnuser_de
- DNS: 1.1.1.1, 8.8.8.8
- MTU: 1400
