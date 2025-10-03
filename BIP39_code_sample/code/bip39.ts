/******************************************************************************************
 *  BIP-39  –  TypeScript implementation  –  Public domain (MIT)  –  2025
 *  نوشتار کاملاً مستقل و بدون وابستگی به ولت‌های تجاری
 *  وابستگی‌ها:
 *      npm i @noble/hashes
 *  (اختیاری) برای تست:
 *      npm i @scure/base
 ******************************************************************************************/
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { readLines } from './vocabReader';

/* ---------- 1.  فهرست لغات انگلیسی BIP-39 (2048 کلمه) ---------- */
const WORDLIST: readonly string[] = Object.freeze(readLines('english.txt'));

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
if (import.meta.url.includes('bip39.ts')) {
// if (import.meta.url === `file://${process.argv[1]}`) {
  const { entropy, mnemonic, seed } = generateMnemonic(128); // 12 کلمه
  console.log('Entropy (hex) :', bytesToHex(entropy));
  console.log('Mnemonic      :', mnemonic);
  console.log('Seed (hex)    :', bytesToHex(seed));
}