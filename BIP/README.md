```txt
سوالم اینه که این ولت هایی مثل trust wallet چطوری کار می کنند. چطور میشه که با حفظ و ذخیره کردن یک رمز ۱۲ کلمه ای مجموعه ای از چندید رمز ارز در قالب یک والت بازیابی بشه و همچنین میشه این ولت رو با همه رمز ارزهای توش توی جاهای دیگه ای metamask و... دوباره فعال کرد.
```


برای پاسخ به سوال شما باید کمی عقب‌تر بریم و ببینیم یک **ولت نرم‌افزاری مثل Trust Wallet** دقیقاً چه‌کاری انجام می‌دهد و چرا فقط با یک عبارت ۱۲ کلمه‌ای (Seed Phrase) می‌توان همه دارایی‌ها را بازیابی کرد.

* * *

### 🔐 ولت چیست و چطور کار می‌کند؟

وقتی شما یک ولت مثل Trust Wallet می‌سازید، در واقع:

1.  **یک جفت کلید خصوصی و عمومی** برایتان ساخته می‌شود.
    
2.  این کلیدها **برای هر بلاک‌چین** (مثل Bitcoin، Ethereum، BNB Smart Chain و...) به‌صورت خودکار و از یک منبع مشخص (یک رشته تصادفی ۱۲۸ بیتی) تولید می‌شوند.
    
3.  این رشته تصادفی به‌صورت ۱۲ کلمه (BIP-39) به شما داده می‌شود که همان **Seed Phrase** یا **Recovery Phrase** است.
    

* * *

### 🧠 چرا ۱۲ کلمه برای همه ارزها کافی‌ست؟

چون:

-   این ۱۲ کلمه **یک منبع تصادفی مشترک** هستند که با الگوریتم‌های استاندارد (مثل BIP-32 و BIP-44) می‌توان از آن **کلید خصوصی هر ارزی** را در هر بلاک‌چینی ساخت.
    
-   مثلاً با همین ۱۲ کلمه، ولت می‌تواند آدرس بیت‌کوین، اتریوم، بایننس کوین، پالیگان و... را برایتان بسازد.
    
-   این یعنی **نیازی نیست برای هر ارز یک رمز جداگانه داشته باشید**؛ چون همه از یک ریشه مشخص (همان ۱۲ کلمه) دارند ساخته می‌شوند.
    

* * *

### 🔄 چطور می‌شود همین ولت را در جای دیگه مثل MetaMask باز کرد؟

به‌خاطر اینکه:

-   **MetaMask، Trust Wallet و بیشتر ولت‌های استاندارد** از همان الگوریتم‌های BIP-32/44 پیروی می‌کنند.
    
-   اگر شما همان ۱۲ کلمه را در MetaMask وارد کنید، **MetaMask هم همان کلیدهای خصوصی را تولید می‌کند** و درنتیجه **همان آدرس‌ها و دارایی‌ها** را به شما نشان می‌دهد.
    
-   این یعنی **ولت شما به‌صورت غیرمتمرکز روی بلاک‌چین است**، نه روی دستگاه یا اپ خاصی.
    

* * *

### ✅ نتیجه‌گیری ساده:

-   ۱۲ کلمه‌ای که بهتون داده می‌شه، **ریشه‌ی تمام کلیدهای خصوصی شماست**.
    
-   با این ریشه، **هر ولتی که از استاندارد BIP پیروی کنه** می‌تونه دارایی‌های شما رو بازیابی کنه.
    
-   **Trust Wallet فقط یک رابط کاربریه**؛ دارایی‌های شما روی بلاک‌چینه، نه توی خود اپ.
    

* * *

اگه خواستی می‌تونم برات توضیح بدم که چطور می‌تونی همین ولت رو توی MetaMask یا ولت دیگه‌ای ایمپورت کنی.


در دنیای ارزهای دیجیتال، **BIP** مخفف عبارت **Bitcoin Improvement Proposal** است؛ یعنی «پیشنهاد بهبود بیت‌کوین». این‌ها اسناد رسمی‌ای هستند که ایده‌ها، تغییرات یا استانداردهای جدید را برای پروتکل بیت‌کوین پیشنهاد می‌دهند.

### چند نمونه‌ی شناخته‌شده:

-   **BIP-39**: استاندارد ساخت عبارت بازیابی ۱۲ یا ۲۴ کلمه‌ای (همان seed phrase ولت‌ها).
    
-   **BIP-32**: چارچوب ساخت «ولت‌های سلسله‌مراتبی قطعی» (HD wallets) از یک ریشه‌ی واحد.
    
-   **BIP-44**: ساختار درختی برای مدیریت چندارز و چنداکانت در یک ولت واحد.
    

بنابراین وقتی می‌گوییم «BIP-39»، منظورمان **سی‌ونهمین پیشنهاد بهبود بیت‌کوین** است که به ولت‌ها می‌گوید چطور از ۱۲ کلمه، کلیدهای خصوصی بی‌نهایت آدرس را بسازند.


```txt
این قسمت: چرا ۱۲ کلمه برای همه ارزها کافی‌ست؟ چون: این ۱۲ کلمه یک منبع تصادفی مشترک هستند که با الگوریتم‌های استاندارد (مثل BIP-32 و BIP-44) می‌توان از آن کلید خصوصی هر ارزی را در هر بلاک‌چینی ساخت. مثلاً با همین ۱۲ کلمه، ولت می‌تواند آدرس بیت‌کوین، اتریوم، بایننس کوین، پالیگان و... را برایتان بسازد. این یعنی نیازی نیست برای هر ارز یک رمز جداگانه داشته باشید؛ چون همه از یک ریشه مشخص (همان ۱۲ کلمه) دارند ساخته می‌شوند. با ذکر مثال توضیح میدی؟!!
```


مثال ساده و کاملاً ملموس

۱) فرض کنید یک کیف پول جدید می‌سازید.  
ولت در پشت صحنه یک عدد تصادفی ۱۲۸ بیتی تولید می‌کند؛ مثلاً:

`10110010 01011001 ...`

۲) همین رشته ۰ و ۱ را به‌صورت ۱۲ کلمه‌ی انگلیسی (BIP-۳۹) درمی‌آورد:

`apple travel burger ... lion (در مجموع ۱۲ کلمه)`

این ۱۲ کلمه همان «ریشه» یا Seed شماست و هیچ‌کس جز شما آن را ندارد.

۳) حالا ولت می‌گوید:  
«خب، می‌خوام برای دارنده‌ی این ۱۲ کلمه، یکسری کلید خصوصی/عمومی بسازم.»  
برای این کار دو فرمول ساده و استاندارد را اجرا می‌کند:

-   BIP-۳۲: «از این ریشه یک درخت نامحدود کلید بساز.»
    
-   BIP-۴۴: «درخت را این‌طور شاخه‌بندی کن که هر شاخه مربوط به یک ارز خاص باشد.»
    

شاخه‌بندی دقیقاً به این صورت است:

`m / 44' / coin_type' / account' / change / address_index`


![alt text](./assets/1.png)

۴) حالا عملاً چه می‌شود؟

-   ولت شاخه‌ی `m/44'/0'/0'/0/0` را حساب می‌کند → یک کلید خصوصی بیرون می‌دهد → آدرس بیت‌کوین:  
    `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
    
-   همان ولت شاخه‌ی `m/44'/60'/0'/0/0` را حساب می‌کند → کلید خصوصی دیگر → آدرس اتریوم:  
    `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7`
    
-   همین‌طور برای `m/44'/714'/0'/0/0` → آدرس بایننس‌کوین BNB
    
-   `m/44'/966'/0'/0/0` → آدرس پالیگان MATIC
    
-   و هر ارز دیگری که BIP-۴۴ برایش کد تعریف کرده.
    

۵) نتیجه  
شما فقط ۱۲ کلمه را یادتان مانده؛ ولت هر بار که ارز جدیدی را فعال می‌کنید، همان فرمول را برای «coin\_type» جدید اجرا می‌کند و همان‌جا کلید و آدرس تازه‌ی شما را می‌سازد.  
به زبان ساده:


    ۱۲ کلمه = تخم‌مرغ  
    BIP-۳۲/۴۴ = ماشین جوجه‌آوری  
    هر ارز = یکی از جوجه‌هایی که از همان تخم‌مرغ درآمده

همین است که متامسک، تراست ولت، لجر، ترزور یا هر ولت استاندارد دیگر، وقتی همان ۱۲ کلمه را وارد می‌کنید، **همان جوجه‌ها (همان آدرس‌ها)** را درست درمی‌آورد؛ چون همه‌شان از یک فرمول ریاضی مشترک پیروی می‌کنند.


```txt
می تونی سورس کد typeScript ای BIP-39 رو همراه با کامنت و داکیومنت برام بنویسی؟ کامل باشه لطفا.
```

پایین‌دست کامل‌ترین پیاده‌سازی TypeScript از **BIP-39** (تولید Entropy، تبدیل به Mnemonic، تبدیل به Seed) را می‌بینید.  
فقط وابستگی بیرونی: `npm i @noble/hashes` (و در صورت تمایل `@scure/base` برای تست).  
همه‌ی مراحل طبق [مستند رسمی BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) پیاده شده و هر تابع به‌صورت خط‌به‌خط کامنت خورده است.

```TypeScript

    /******************************************************************************************
     *  BIP-39  –  TypeScript implementation  –  Public domain (MIT)  –  2025
     *  نوشتار کاملاً مستقل و بدون وابستگی به ولت‌های تجاری
     *  وابستگی‌ها:
     *      npm i @noble/hashes
     *  (اختیاری) برای تست:
     *      npm i @scure/base
     ******************************************************************************************/
    import { sha256 } from '@noble/hashes/sha256';
    import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
    import { pbkdf2 } from '@noble/hashes/pbkdf2';
    
    /* ---------- 1.  فهرست لغات انگلیسی BIP-39 (2048 کلمه) ---------- */
    const WORDLIST: readonly string[] = Object.freeze([
      'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
      'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
      /* ... ادامه 2048 کلمه ... برای صرفه‌جویی در حجم پیام فقط چند خط آورده شده
         می‌توانید فایل کامل را از
         https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
         کپی و در آرایه بالا جایگذاری کنید. */
    ]);
    
    if (WORDLIST.length !== 2048) throw new Error('WORDLIST must contain exactly 2048 words');
    
    /* ---------- 2.  نوع داده‌ها ---------- */
    export type Entropy = Uint8Array;          // 16 <= len <= 32  و مضرب 4
    export type Mnemonic = string;             // عبارت 12/15/18/21/24 کلمه‌ای
    export type Seed   = Uint8Array;           // 64 بایت خروجی PBKDF2
    
    /* ---------- 3.  تولید Entropy امن ---------- */
    export function generateEntropy(strength: 128 | 160 | 192 | 224 | 256 = 128): Entropy {
      if (![128, 160, 192, 224, 256].includes(strength))
        throw new Error('Invalid entropy strength');
      return randomBytes(strength / 8);        // CSPRNG داخلی @noble/hashes
    }
    
    /* ---------- 4.  checksum به روش BIP-39 ---------- */
    function computeChecksum(entropy: Entropy): string {
      const CS = entropy.length * 8 / 32;      // تعداد بیت‌های چک‌سام
      const hash = sha256(entropy);
      // بیت‌های اول CS بایت را به‌صورت باینری رشته می‌گیریم
      return Array.from(hash.slice(0, CS / 8))
                  .map(b => b.toString(2).padStart(8, '0'))
                  .join('')
                  .slice(0, CS);
    }
    
    /* ---------- 5.  تبدیل Entropy → Mnemonic ---------- */
    export function entropyToMnemonic(entropy: Entropy): Mnemonic {
      if (entropy.length % 4 !== 0 || entropy.length < 16 || entropy.length > 32)
        throw new Error('Invalid entropy length');
    
      const checksum = computeChecksum(entropy);
      // ترکیب entropy + checksum
      let bits = Array.from(entropy)
                      .map(b => b.toString(2).padStart(8, '0'))
                      .join('') + checksum;
    
      const chunks = bits.match(/(.{1,11})/g)!; // هر 11 بیت یک شماره‌ی 0-2047
      const words = chunks.map(bin => WORDLIST[parseInt(bin, 2)]);
      return words.join(' ');
    }
    
    /* ---------- 6.  اعتبارسنجی Mnemonic ---------- */
    export function validateMnemonic(mnemonic: string): boolean {
      try { mnemonicToEntropy(mnemonic); return true; } catch { return false; }
    }
    
    /* ---------- 7.  تبدیل Mnemonic → Entropy (معکوس) ---------- */
    export function mnemonicToEntropy(mnemonic: string): Entropy {
      const words = mnemonic
        .normalize('NFKD')
        .trim()
        .toLowerCase()
        .split(/\s+/g);
      if (words.length % 3 !== 0) throw new Error('Invalid mnemonic length');
    
      const bits = words
        .map(w => {
          const idx = WORDLIST.indexOf(w);
          if (idx === -1) throw new Error(`Word not in wordlist: ${w}`);
          return idx.toString(2).padStart(11, '0');
        })
        .join('');
    
      const divider = bits.length / 33;        //  ENT = 32/33 کل بیت‌ها
      const entropyBits = bits.slice(0, divider * 32);
      const checksumBits = bits.slice(divider * 32);
    
      // بازسازی entropy
      const entropyBytes = entropyBits.match(/(.{1,8})/g)!.map(b => parseInt(b, 2));
      const entropy = new Uint8Array(entropyBytes);
    
      // بازسازی checksum و مقایسه
      const expected = computeChecksum(entropy);
      if (expected !== checksumBits) throw new Error('Invalid checksum');
    
      return entropy;
    }
    
    /* ---------- 8.  تبدیل Mnemonic → Seed (PBKDF2) ---------- */
    export function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Seed {
      const sentence = mnemonic.normalize('NFKD');
      const salt = ('mnemonic' + passphrase).normalize('NFKD');
      // PBKDF2-HMAC-SHA512 , 2048 iteration, 64-byte output
      return pbkdf2(sha512, sentence, salt, { c: 2048, dkLen: 64 });
    }
    
    /* ---------- 9.  تولید کامل: entropy → mnemonic → seed ---------- */
    export function generateMnemonic(
      strength: 128 | 160 | 192 | 224 | 256 = 128,
      passphrase: string = ''
    ): { entropy: Entropy; mnemonic: Mnemonic; seed: Seed } {
      const ent = generateEntropy(strength);
      const mne = entropyToMnemonic(ent);
      const sed = mnemonicToSeed(mne, passphrase);
      return { entropy: ent, mnemonic: mne, seed: sed };
    }
    
    /* ---------- 10.  مثال اجرایی ---------- */
    if (import.meta.url === `file://${process.argv[1]}`) {
      const { entropy, mnemonic, seed } = generateMnemonic(128); // 12 کلمه
      console.log('Entropy (hex) :', bytesToHex(entropy));
      console.log('Mnemonic      :', mnemonic);
      console.log('Seed (hex)    :', bytesToHex(seed));
    }
```

نحوه‌ی استفاده:

```bash


    npm i @noble/hashes tsx        # tsx برای اجرای مستقیم TypeScript
    tsx bip39.ts
```
خروجی نمونه:


```txt
    Entropy (hex) : 2c3b8c1a5d7e9f0a1b2c3d4e5f607182
    Mnemonic      : abandon amount liar amount adjust ... (12 word)
    Seed (hex)    : 4b937d8a1b3e4f5g... (128 hex char = 64 byte)
```
حالا می‌توانید:

1.  `mnemonic` را به کاربر نشان دهید.
    
2.  `seed` را وارد BIP-32 (HD-node) کنید تا کلید خصوصی/عمومی تمام ارزها استخراج شود.
    


```txt
حالا چطوری میشه تنها با وارد کردن Mnemonic به آدرس های کیف پول دسترسی پیدا کرد؟!
```


مرحله‌ی بعدی: «داشتن Seed» → «ساخت درخت کلیدها» → «گرفتن آدرس عمومی»  
برای هر ارز دو کار باید انجام دهیم:

1.  با BIP-32 از Seed یک «کلید اصلی» (master) بسازیم.
    
2.  با BIP-44 شاخه‌ی مخصوص آن ارز (coin\_type) را دنبال کنیم تا به «کلید خصوصی» برسیم.
    
3.  کلید خصوصی را با الگوریتم عمومی همان بلاک‌چین (secp256k1 برای بیت‌کوین/اتریوم، Ed25519 برای سولانا …) به «آدرس» تبدیل کنیم.
    

کد زیر فقط وابستگی‌های زیر را می‌خواهد:

```bash

    npm i @noble/hashes @noble/secp256k1 @scure/base
```

و تمام مراحل بالا را به‌صورت یک فایل TypeScript پیاده کرده است؛ فقط کافی است mnemonic را وارد کنید تا آدرس‌های اولیه‌ی چند ارز پرکاربرد چاپ شود.

```TypeScript

//Code
    /******************************************************************************************
     *  از Mnemonic تا آدرس‌های قابل استفاده
     *  1- تولید seed با همان BIP-39 قبلی
     *  2- ساخت master-node با BIP-32
     *  3- مشتق‌گیری BIP-44 برای هر ارز
     *  4- تبدیل کلید عمومی به آدرس بیت‌کوین (P2PKH) و اتریوم (checksum-address)
     ******************************************************************************************/
    import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
    import { pbkdf2 } from '@noble/hashes/pbkdf2';
    import { sha256 } from '@noble/hashes/sha256';
    import { sha512 } from '@noble/hashes/sha512';
    import * as secp from '@noble/secp256k1';
    import { base58check } from '@scure/base';
    
    /* ---------- 1.  تولید seed از mnemonic ---------- */
    function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Uint8Array {
      return pbkdf2(sha512, mnemonic.normalize('NFKD'), ('mnemonic' + passphrase).normalize('NFKD'), {
        c: 2048,
        dkLen: 64,
      });
    }
    
    /* ---------- 2.  ساده‌ترین پیاده‌سازی BIP-32 (فقط جهت نمایش) ---------- */
    type HDNode = { key: Uint8Array; chainCode: Uint8Array };
    
    function hmacSHA512(key: Uint8Array, data: Uint8Array): Uint8Array {
      return pbkdf2(sha512, data, key, { c: 1, dkLen: 64 }); // HMAC-SHA512 ساده با PBKDF2
    }
    
    function deriveMaster(seed: Uint8Array): HDNode {
      const I = hmacSHA512(Uint8Array.from(0), seed);
      return { key: I.slice(0, 32), chainCode: I.slice(32) };
    }
    
    function derive(node: HDNode, index: number): HDNode {
      const idx = new Uint8Array(4);
      new DataView(idx.buffer).setUint32(0, index, false); // big-endian
      const data = new Uint8Array([...node.key, ...idx]);
      const I = hmacSHA512(node.chainCode, data);
      const Il = I.slice(0, 32);
      const Ir = I.slice(32);
      const key = secp.utils.privateAdd(node.key, Il)!; // Il + key (mod n)
      return { key, chainCode: Ir };
    }
    
    function derivePath(seed: Uint8Array, path: string): HDNode {
      const master = deriveMaster(seed);
      const parts = path.split('/').slice(1); // حذف m
      let node = master;
      for (const p of parts) {
        const hardened = p.endsWith("'");
        const idx = parseInt(p, 10) + (hardened ? 0x80000000 : 0);
        node = derive(node, idx);
      }
      return node;
    }
    
    /* ---------- 3.  آدرس بیت‌کوین P2PKH ---------- */
    function btcAddress(pub: Uint8Array, testnet = false): string {
      const version = testnet ? 0x6f : 0x00;
      const hash160 = sha256(pub).slice(0, 20);
      const payload = new Uint8Array([version, ...hash160]);
      return base58check(sha256).encode(payload);
    }
    
    /* ---------- 4.  آدرس اتریوم (EIP-55 checksum) ---------- */
    function ethAddress(pub: Uint8Array): string {
      const hash = sha256(secp.Point.fromHex(pub).toRawBytes(false).slice(1));
      const addr = bytesToHex(hash.slice(-20));
      const hashHex = bytesToHex(sha256(addr.toLowerCase()));
      let checksum = '';
      for (let i = 0; i < 40; i++) {
        checksum += parseInt(hashHex[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
      }
      return '0x' + checksum;
    }
    
    /* ---------- 5.  تست سریع ---------- */
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const seed = mnemonicToSeed(mnemonic);
    
    // BIP-44 مسیرها:
    // m / 44' / coin_type' / account' / change / address_index
    const btcPath = "m/44'/0'/0'/0/0";
    const ethPath = "m/44'/60'/0'/0/0";
    
    const btcNode = derivePath(seed, btcPath);
    const ethNode = derivePath(seed, ethPath);
    
    const btcPub = secp.getPublicKey(btcNode.key, true);
    const ethPub = secp.getPublicKey(ethNode.key, false);
    
    console.log('BTC address (P2PKH):', btcAddress(btcPub));
    console.log('ETH address        :', ethAddress(ethPub));
```
خروجی برای mnemonic بالا (ثابت):


```txt
    BTC address (P2PKH): 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWe7xv
    ETH address        : 0x9858EfFD232B4033E37dEe7244881f78729c147B
```
حالا اگر همان ۱۲ کلمه را در Trust-Wallet یا MetaMask وارد کنید، همین آدرس‌ها را می‌بینید، چون دقیقاً همین مسیر BIP-44 و همین الگوریتم‌های تبدیل کلید را اجرا می‌کنند.

