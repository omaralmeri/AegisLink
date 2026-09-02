# 🛡️ AegisLink v2.0 - Advanced Cyber Threat URL & Domain Intelligence Scanner

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Standard%20Lib)-orange.svg)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

AegisLink هي أداة فحص وتحليل أمني احترافية للروابط ونطاقات الويب (URL & Domain Security Intelligence Scanner)، مصممة لخبراء الأمن السيبراني ومحققي الحوادث الأمنية والمهتمين بتحليل الروابط المشبوهة وهجمات التصيد الاحتيالي (Phishing).

تتميز الأداة بواجهة سطر أوامر (CLI) أنيقة وعصرية، مع مؤشرات ألوان واضحة متوافقة تماماً وبشكل تلقائي مع أنظمة Windows و Linux دون الحاجة لتثبيت أي مكتبات خارجية معقدة.

---

## ✨ المميزات الرئيسية (Core Features)

1. **🌐 تحليل البنية التحتية ونظام الأسماء (DNS & Infrastructure Intelligence):**
   - كشف عناوين الـ IP المرتبطة بالنطاق (A / CNAME Records).
   - الفحص العكسي لـ IP (Reverse DNS Lookup).
   - كشف العناوين الخاصة والمحلية (RFC 1918 Private IP Detection).

2. **🔒 التدقيق الأمني لشهادات التشفير (SSL / TLS Cryptographic Audit):**
   - فحص صحة الشهادة والجهة المصدرة (Certificate Authority).
   - حساب الأيام المتبقية لانتهاء الصلاحية والتنبيه المبكر.
   - التحقق من بروتوكول التشفير وخوارزمية التشفير (Cipher Suite).

3. **⚡ تتبع سلاسل إعادة التوجيه والسرعة (HTTP & Redirection Tracking):**
   - تتبع كامل لكافة محطات إعادة التوجيه (Hop-by-Hop Redirect Tracing) لكشف الروابط المختصرة والمموهة (bit.ly, tinyurl, etc.).
   - قياس زمن الاستجابة (Latency in ms).
   - استخراج نوع الخادم وترميز المحتوى.

4. **🛡️ فحص وترميز ترويسات الأمان (HTTP Security Headers Audit):**
   - فحص وجود ترويسات الحماية: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   - إعطاء تقييم أمني دقيق (Grade: A+, A, B, C, F) مع توضيح الثغرات الناتجة عن غيابها.

5. **🚩 كشف الأنماط المشبوهة والتصيد الاحتيالي (Heuristic Threat Detection):**
   - كشف استخدام عناوين الـ IP المباشرة كبديل للنطاقات.
   - كشف هجمات الاحتيال البصري (IDN / Punycode Homograph Attacks).
   - كشف الكلمات المفتاحية الحساسة لسرقة الهوية والبيانات المالية.
   - كشف النطاقات ذات السمعة المشبوهة (High-abuse TLDs).
   - كشف روابط الملفات التنفيذية والبرمجيات الخبيثة المباشرة (.exe, .vbs, .apk, etc.).

6. **📊 مؤشر التهديد والتقرير النهائي (Threat Score & Verdict):**
   - حساب مؤشر خطورة رقمي (0 - 100).
   - شريط تقدم ملون وتقييم حاسم: [SAFE], [MODERATE], [WARNING], [CRITICAL].
   - دعم التصدير لملفات JSON والفحص الجماعي عبر ملفات نصية.

---

## 💻 متطلبات التشغيل والتثبيت (Installation)

الأداة تعتمد بنسبة 100% على مكتبات بايثون القياسية (Pure Python Standard Library)، ولا تحتاج لأي تثبيت عبر pip.

### 1. المتطلبات:
- تثبيت بايثون 3.8 أو أحدث (python3).

### 2. التثبيت على لينكس (Linux):
```bash
git clone https://github.com/USERNAME/AegisLink.git
cd AegisLink
chmod +x aegislink.py
python3 aegislink.py --help
```

### 3. التثبيت على ويندوز (Windows):
افتح موجه الأوامر (CMD) أو PowerShell:
```cmd
git clone https://github.com/USERNAME/AegisLink.git
cd AegisLink
python aegislink.py --help
```

---

## 🚀 كيفية استخدام الأداة (Usage Guide)

### 1. فحص رابط فردي (Single Scan):
```bash
python3 aegislink.py https://example.com
```

### 2. فحص رابط وتصدير التقرير إلى JSON:
```bash
python3 aegislink.py https://target-site.com -o report.json
```

### 3. فحص قائمة روابط دفعة واحدة من ملف نصي (Batch Scan):
قم بإنشاء ملف urls.txt يحتوي على الروابط (رابط في كل سطر)، ثم نفذ:
```bash
python3 aegislink.py -f urls.txt -o results.json
```

### 4. الوضع الصامت للمهام المؤتمتة (Quiet Mode):
```bash
python3 aegislink.py https://example.com -q
```

### 5. تحديد مهلة الاتصال (Custom Timeout):
```bash
python3 aegislink.py https://example.com -t 15
```

---

## 📜 الترخيص (License)
هذا المشروع مرخص تحت رخصة MIT. يمكنك استخدامه وتطويره بحرية.

