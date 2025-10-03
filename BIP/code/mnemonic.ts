/******************************************************************************************
 *  از Mnemonic تا آدرس BTC / ETH
 *  ورژن‌های قطعی:
 *      @noble/hashes 2.0.1  –  @noble/curves 1.x  –  @scure/base 2.0.0
 ******************************************************************************************/
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';   // ← تغییر اصلی
import { base58check } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3.js';

/* ---------- helper: bytes ↔ bigint ---------- */
const bytesToBig = (b: Uint8Array): bigint =>
  BigInt('0x' + bytesToHex(b));

const bigToBytes = (n: bigint, len: number): Uint8Array => {
  let h = n.toString(16);
  if (h.length & 1) h = '0' + h;
  return hexToBytes(h.padStart(len * 2, '0'));
};

const mod = (a: bigint, b: bigint): bigint => ((a % b) + b) % b;

/* ---------- 1.  BIP-39 seed ---------- */
function mnemonicToSeed(mnemonic: string, passphrase = ''): Uint8Array {
  const pwd  = Buffer.from(mnemonic.normalize('NFKD'), 'utf8');
  const salt = Buffer.from(('mnemonic' + passphrase).normalize('NFKD'), 'utf8');
  return pbkdf2(sha512, pwd, salt, { c: 2048, dkLen: 64 });
}

/* ---------- 2.  BIP-32 ---------- */
type HDNode = { key: Uint8Array; chainCode: Uint8Array };

const hmacSHA512 = (key: Uint8Array, data: Uint8Array): Uint8Array =>
  hmac(sha512, key, data);

const deriveMaster = (seed: Uint8Array): HDNode => {
  const I = hmacSHA512(Buffer.from('Bitcoin seed', 'utf8'), seed);
  return { key: I.slice(0, 32), chainCode: I.slice(32) };
};

const u32be = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};

const derive = (node: HDNode, index: number): HDNode => {
  const isHardened = index >= 0x80000000;
  const data = isHardened
    ? new Uint8Array([0, ...node.key, ...u32be(index)])
    : new Uint8Array([...secp256k1.getPublicKey(node.key, false), ...u32be(index)]);

  const I  = hmacSHA512(node.chainCode, data);
  const Il = I.slice(0, 32);
  const Ir = I.slice(32);

  const a = bytesToBig(node.key);
  const b = bytesToBig(Il);
  const k = mod(a + b, BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));   // ← حالا n را داریم
  const key = bigToBytes(k, 32);

  return { key, chainCode: Ir };
};

const derivePath = (seed: Uint8Array, path: string): HDNode => {
  let node = deriveMaster(seed);
  path.split('/').slice(1).forEach(p => {
    const i = parseInt(p.replace("'", ''), 10) + (p.endsWith("'") ? 0x80000000 : 0);
    node = derive(node, i);
  });
  return node;
};

/* ---------- 3.  BTC P2PKH address ---------- */
const btcAddr = (pub: Uint8Array, testnet = false) => {
  const ver = testnet ? 0x6f : 0x00;
  const hash160 = ripemd160(sha256(pub));
  return base58check(sha256).encode(new Uint8Array([ver, ...hash160]));
};

/* ---------- 4.  ETH EIP-55 address ---------- */
const ethAddr = (pub: Uint8Array) => {
  const hash = keccak_256(pub.slice(1)); // remove 0x04 prefix
  const addr = bytesToHex(hash.slice(-20));
  const uint8arrAddr = Uint8Array.from(addr.toLowerCase().split('').map(letter => letter.charCodeAt(0)));
  const hashHex = bytesToHex(keccak_256(uint8arrAddr));
  let chk = '';
  for (let i = 0; i < 40; i++)
    chk += parseInt(hashHex[i], 16) >= 8 ? addr[i].toUpperCase() : addr[i];
  return '0x' + chk;
};

/* ---------- 5.  test ---------- */
const mnemonic = 'clog essay release slim furnace common bounce bicycle eight cruel spend auction';
// const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = mnemonicToSeed(mnemonic);

const btcNode = derivePath(seed, "m/44'/0'/0'/0/0");
const ethNode = derivePath(seed, "m/44'/60'/0'/0/0");

const btcPub = secp256k1.getPublicKey(btcNode.key, true);  // compressed
const ethPub = secp256k1.getPublicKey(ethNode.key, false); // uncompressed

console.log('BTC:', btcAddr(btcPub));
console.log('ETH:', ethAddr(ethPub));