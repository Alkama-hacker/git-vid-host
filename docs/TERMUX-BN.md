# Termux-এ GVH SHIELD ব্যবহারের সম্পূর্ণ গাইড

এই গাইডটা ফোনের Termux থেকেই শুরু থেকে শেষ — ইনস্টল, সাইট সিল করা, টেস্ট করা,
হোস্টে আপলোড করা, আর সমস্যা হলে কী করবেন।

> টুলটা শুধু **Python standard library + PHP** দিয়ে চলে। কোনো বড় ফ্রেমওয়ার্ক,
> Docker বা ডাটাবেস লাগে না। ইন্টারনেটও লাগে না — সব কাজ ফোনেই হয়।

---

## 0. এক নজরে

```
আপনার index.html  ──gvh build──►  secured/index.php   ──upload──►  আপনার হোস্টিং
                    (এনক্রিপ্ট)      (+ vault_xxxx/)     (PHP+HTTPS)
```

- **Termux-এ যা করবেন:** সাইট সিল করা (`gvh build`)
- **হোস্টে যা লাগবে:** PHP 7.2+ (openssl + zlib) আর **HTTPS**
- **আপলোড করবেন:** শুধু `secured/` ফোল্ডারের ভিতরের জিনিস

---

## 1. Termux ইনস্টল ও প্রস্তুতি

Play Store-এর Termux পুরনো — **F-Droid** বা GitHub থেকে নিন:
<https://f-droid.org/packages/com.termux/>

```bash
# প্যাকেজ লিস্ট আপডেট
pkg update -y && pkg upgrade -y

# যা যা লাগবে
pkg install -y python php git openssl-tool

# ভার্সন দেখে নিন (Python 3.7+, PHP 7.2+ দরকার)
python3 --version
php -v

# সবচেয়ে গুরুত্বপূর্ণ: PHP-তে openssl আর zlib আছে কি না
php -m | grep -E "openssl|zlib"
```

`openssl` আর `zlib` — দুটোই দেখতে হবে। না দেখলে:

```bash
pkg install -y php-openssl php-zlib
```

> **মোবাইলের স্টোরেজ:** ডিফল্টে Termux শুধু নিজের হোমে লেখে। আপনার সাইট
> `~/storage/downloads/...`-এ থাকলে একবার এটা চালান:
>
> ```bash
> termux-setup-storage      # পারমিশন চাইবে, Allow দিন
> ls ~/storage/downloads    # ভিতরে আপনার ফাইল দেখা উচিত
> ```

---

## 2. টুলটা নামানো

```bash
cd ~
git clone https://github.com/Alkama-hacker/git-vid-host.git
cd git-vid-host

# টুলটা চালু আছে কি না দেখুন
./gvh version
```

আউটপুট এমন হবে:

```
GVH SHIELD 1.0.0 · SECURED BY @SHACKER_ENCRYPTION_bot · DEV Shacker · @Haki_xmw
```

`Permission denied` এলে:

```bash
chmod +x gvh
./gvh version
```

### নিজের কম্যান্ড বানিয়ে নিন (ঐচ্ছিক, কিন্তু সুবিধাজনক)

```bash
mkdir -p ~/bin
ln -sf ~/git-vid-host/gvh ~/bin/gvh
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
gvh version          # এখন যেকোনো ফোল্ডার থেকে শুধু `gvh`
```

---

## 3. নিজের সাইট সিল করা (মূল কাজ)

### ৩.১ সাইটটা এক ফোল্ডারে রাখুন

```
mysite/
├── index.html
└── assets/
    ├── style.css
    ├── app.js
    ├── logo.svg
    └── hero.png
```

CSS/JS/ছবি **আলাদা ফাইলে** থাকলে ভালো — ছোট inline `<style>`/`<script>`-ও কাজ
করে, কিন্তু আলাদা ফাইল হলে এনক্রিপ্টেড vault-এ যায় এবং বেশি সুরক্ষিত থাকে।

### ৩.২ আগে দেখে নিন (কিছু লেখা হয় না)

```bash
cd ~/git-vid-host
./gvh inspect ~/mysite/index.html
```

এটা বলবে কী কী server-side যাবে, কী client-side থাকবে, কতগুলো ছবি/ভিডিও
vault-এ যাবে। কিছু ভাঙার ভয় নেই — এটা শুধু রিপোর্ট।

### ৩.৩ এবার সিল করুন

```bash
./gvh build ~/mysite/index.html -o ~/mysite-secured --force
```

সফল হলে:

```
────── BUILD COMPLETE ────────────────────────────────
  ✔ output      : /home/.../mysite-secured/index.php
  ✔ size        : 128.7 KB  (shell 116.3 KB + content 2.5 KB)
  ✔ chunks      : 1 sealed content chunks · 50 engine chunks
  ✔ api keys    : 1 (one AES-256 key per chunk) + 24 decoys
  ✔ media vault : embedded in index.php
```

সাথে দুটো ফাইল তৈরি হবে — **এগুলো কখনো আপলোড করবেন না** (এতে id/keys থাকে):

```
mysite-secured.report.json     ← অডিট রিপোর্ট, নিজের কাছে রাখুন
mysite-secured.DEPLOY.txt      ← ডিপ্লয় নোট
```

### ৩.৪ ফলাফল

```
mysite-secured/
└── index.php          ← এটাই আপনার নতুন সাইট (একটাই ফাইল)
    vault_xxxxxxxx/    ← শুধু বড় ভিডিও/ছবি থাকলে তৈরি হয়
```

আপনার আসল `index.html` আর `assets/` অক্ষত থাকে — ওগুলো নিজের কাছে রাখুন।

---

## 4. ফোনেই টেস্ট করা

PHP এখন Termux-এ আছে, তাই ল্যাপটপ ছাড়াই ব্রাউজ করে দেখতে পারবেন:

```bash
./gvh serve ~/mysite-secured
# → http://localhost:8080  (ফোনের Chrome-এ খুলুন)
```

- পেজ ভাঙা/সিল করা দেখলে → ঠিক আছে
- এক-দুই সেকেন্ডে আসল ডিজাইন এসে যাবে
- **F12 / right click / Kiwi ব্রাউজার** — ওয়াইপ + রিডাইরেক্ট

> `--allow-iframe` ছাড়া পেজটা নিজের ভিতরেই একটা same-origin iframe-এ রেন্ডার
> হয়; বাইরের DOM-এ শুধু `<iframe>` থাকে।

কোথাও আটকে গেলে:

```bash
./gvh doctor          # python ✔ / php ✔ / openssl ✔ দেখুন
./gvh check ~/mysite-secured   # এক মিনিটের স্মোক টেস্ট
```

---

## 5. হোস্টিংয়ে আপলোড

### ৫.১ কী আপলোড করবেন

| আপলোড করবেন | আপলোড **করবেন না** |
|---|---|
| `mysite-secured/` এর **ভিতরের সব** (`index.php`, `vault_*`) | `*.report.json`, `*.DEPLOY.txt` |
| — | আসল `index.html`, `assets/` (আপনার সোর্স) |

cPanel/FTP-তে `public_html/`-এর ভিতরে `index.php` আর (থাকলে) `vault_xxxx/`
ফোল্ডার তুলে দিন।

### ৫.২ হোস্টে যা অবশ্যই লাগবে

1. **PHP 7.2 বা তার উপরে** — `openssl` আর `zlib` এক্সটেনশনসহ
2. **HTTPS** (লেটার দিয়ে `<https://...>`)

`http://`-তে পেজ খুলবে না — ব্রাউজার WebCrypto বন্ধ রাখে। শুধু
`http://localhost` এর ব্যতিক্রম।

### ৫.৩ এক নাম্বার ভুল যেটা সবাই করে

সাইটটা কোনো **iframe-এ রেখে** দেখাবেন না। জেনারেট করা `index.php` নিজেই
`X-Frame-Options: DENY`, `CSP frame-ancestors 'none'` আর JS গার্ড দিয়ে
অন্য সাইটে embed হওয়া বন্ধ করে।

---

## 6. সাধারণ কাজের উদাহরণ

```bash
# ছোট সাইট, সব একটাই index.php
./gvh build index.html -o out --force

# অনেক বড় ভিডিও (vault ফোল্ডার বানাবে)
./gvh build index.html -o out --asset-mode files --force

# ডিফল্ট রিডাইরেক্ট বদলানো
./gvh build index.html -o out --deny-url https://my.site/denied --force

# নিজের সাইটের আরেক পেজে embed করতে চাই (staging)
./gvh build index.html -o out --allow-iframe --force

# শুধু অডিট, কিছু লিখবে না
./gvh inspect index.html

# JSON রিপোর্ট (স্ক্রিপ্টের জন্য)
./gvh build index.html -o out --quiet --json --force

# ভাঙা সাইট ডিবাগ করা (গার্ডগুলো বন্ধ)
./gvh build index.html -o out --allow-hooks --allow-non-native --force
```

> ⚠️ `--allow-*` ফ্ল্যাগগুলো দুর্বল করে। শুধু ডিবাগ করার সময়, শেষে আবার
> ফ্ল্যাগ ছাড়া বিল্ড করুন।

---

## 7. সব ফ্ল্যাগ (সংক্ষেপে)

| ফ্ল্যাগ | কাজ |
|---|---|
| `-o, --output DIR` | আউটপুট ফোল্ডার (`<input>-secured/` ডিফল্ট) |
| `--asset-mode auto\|embed\|files` | ছবি/ভিডিও index.php-এ ঢুকবে না আলাদা ফাইল হবে |
| `--deny-url URL` | ডিটেকশনে কোথায় পাঠাবে |
| `--chunk-size N` | কত বড় চাঙ্ক (ডিফল্ট 16384) |
| `--inline-limit N` | কত বাইট পর্যন্ত ছবি data: URI হবে |
| `--allow-crawlers` | সার্চ ইঞ্জিন বট ছাড়বে |
| `--allow-webview` | ইন-অ্যাপ ব্রাউজার ছাড়বে |
| `--allow-dynamic` | রানটাইমে script/iframe ঢোকানো ছাড়বে |
| `--allow-iframe` | অন্য সাইটে embed করা ছাড়বে |
| `--allow-non-native` | emulator/টেস্ট ব্রাউজারের জন্য হুক-চেক বন্ধ |
| `--allow-hooks` | hook scan বন্ধ (dev only) |
| `--allow-print` / `--no-select` / `--no-rightclick` | প্রিন্ট/সিলেক্ট/রাইট-ক্লিক ছাড়বে |
| `--keep-comments` | HTML কমেন্ট রাখবে (পাবলিক হয়ে যাবে) |
| `--ua-extra REGEX` | নির্দিষ্ট UA ব্লক |
| `--force` | পুরনো আউটপুট ফোল্ডার ওভাররাইট |
| `--quiet` / `--json` | স্ক্রিপ্টিং মোড |

---

## 8. সমস্যা ও সমাধান

| দেখছেন | কারণ | সমাধান |
|---|---|---|
| `php: not found` | PHP ইনস্টল নেই | `pkg install php php-openssl` |
| `PHP openssl extension is missing` | openssl নেই | `pkg install php-openssl` → `php -m` দিয়ে দেখুন |
| `Output folder not empty` | আগের বিল্ড আছে | `--force` দিন বা নতুন `-o` |
| সাদা পেজ / "secure relay did not answer" | PHP চলছে না বা HTTPS নেই | হোস্টে PHP 7.2+ ও HTTPS নিশ্চিত করুন |
| "needs a modern browser" | WebCrypto নেই (HTTP বা পুরনো ব্রাউজার) | HTTPS ব্যবহার করুন |
| পেজ খুলেই "Nice Try Hacker" | আপনি curl/webview/iframe/সার্ভারে দেখছেন | আসল ব্রাউজারে সরাসরি URL খুলুন |
| `vault_*` ফোল্ডার আপলোড করতে ভুলে গেছেন | বড় মিডিয়া files mode-এ | দুটোই একসাথে আপলোড করুন |
| ফাইল পারমিশন এরর | `gvh` এক্সিকিউটেবল নয় | `chmod +x gvh` |
| `termux-setup-storage` কাজ করছে না | পারমিশন দেওয়া হয়নি | সেটিংস → Apps → Termux → Permissions → Files |

---

## 9. আপডেট ও নতুন বিল্ড

```bash
cd ~/git-vid-host
git pull
./gvh version

# সাইট বদলালে আবার বিল্ড করুন, পুরনো index.php মুছে ফেলুন
./gvh build ~/mysite/index.html -o ~/mysite-secured --force
```

হোস্টে নতুন `index.php` (আর বদলালে `vault_*`) আপলোড করে পুরনোটা রিপ্লেস করুন।
পুরনো বিল্ডের সাথে নতুন vault মিশাবেন না — দুটো আলাদা বিল্ড।

---

## 10. মনে রাখবেন

- এটা **DRM নয়**। ব্রাউজার যা দেখাতে পারে, সেই ব্রাউজারই কোনোভাবে তা বের করতে
  পারে — আমরা শুধু খরচ ও ঝামেলা অনেক বাড়িয়ে দিই।
- **সার্চ ইঞ্জিনে সাইটটা ইনডেক্স হবে না** (বট ব্লক করা ডিজাইনগত)।
- সাইটের নিজের কোড ঠিক থাকে — এনক্রিপশন শুধু পরিবহন আর কপি করা কঠিন করে।
- অডিট রিপোর্ট (`*.report.json`) কখনো পাবলিক ফোল্ডারে রাখবেন না।

সব কিছু ঠিক থাকলে এই কম্যান্ডটা চালিয়ে নিশ্চিত হয়ে নিন:

```bash
./gvh doctor && ./gvh check ~/mysite-secured
```
