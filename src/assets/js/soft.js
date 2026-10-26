/* ==========================================================================
 *  GVH SHIELD :: software crypto fallback (no WebCrypto needed)
 *  --------------------------------------------------------------------------
 *  Some Android WebView / Chromium builds ship a subtly broken
 *  `crypto.subtle` (PBKDF2 or AES-GCM reject with OperationError even for
 *  valid input).  When that happens the sealed page must still open, so this
 *  file implements the same primitives in plain ES5:
 *
 *      sha256(bytes)                       -> Uint8Array
 *      hmacSha256(key, msg)                -> Uint8Array
 *      pbkdf2Sha256(pass, salt, iter, len) -> Uint8Array
 *      aesGcmOpen(key, iv, ctAndTag)       -> Uint8Array  (throws "auth")
 *
 *  Same key material, same wire format, same authenticated tag - only slower.
 *  Deliberately byte-oriented (no lookup-table bit tricks) so that it can be
 *  verified line by line against any reference implementation.
 *
 *  Exposed as:  window.GVH_SOFT = { sha256, hmac, pbkdf2, gcmOpen }
 * ========================================================================== */
(function (W) {
  'use strict';

  /* ---------------------------------------------------------------- SHA-256 */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256block(H, W32, p) {
    var i, t1, t2, a, b, c, d, e, f, g, h, x, y;
    for (i = 0; i < 16; i++) {
      W32[i] = ((p[i * 4] << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) | p[i * 4 + 3]) >>> 0;
    }
    for (i = 16; i < 64; i++) {
      x = W32[i - 15]; y = W32[i - 2];
      W32[i] = ((((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) +
        (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) +
        W32[i - 7] + W32[i - 16]) >>> 0;
    }
    a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
    for (i = 0; i < 64; i++) {
      t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
        ((e & f) ^ (~e & g)) + K[i] + W32[i]) >>> 0;
      t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
        ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  function sha256(msg) {
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var W32 = new Array(64);
    var len = msg.length;
    var total = ((len + 9 + 63) >> 6) << 6;
    var padded = new Uint8Array(total);
    padded.set(msg);
    padded[len] = 0x80;
    var bits = len * 8;
    var hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
    padded[total - 8] = (hi >>> 24) & 255; padded[total - 7] = (hi >>> 16) & 255;
    padded[total - 6] = (hi >>> 8) & 255; padded[total - 5] = hi & 255;
    padded[total - 4] = (lo >>> 24) & 255; padded[total - 3] = (lo >>> 16) & 255;
    padded[total - 2] = (lo >>> 8) & 255; padded[total - 1] = lo & 255;
    for (var off = 0; off < total; off += 64) sha256block(H, W32, padded.subarray(off, off + 64));
    var out = new Uint8Array(32);
    for (var i = 0; i < 8; i++) {
      out[i * 4] = (H[i] >>> 24) & 255; out[i * 4 + 1] = (H[i] >>> 16) & 255;
      out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255;
    }
    return out;
  }

  /* ------------------------------------------------------------ HMAC-SHA256 */
  function hmac(key, msg) {
    if (key.length > 64) key = sha256(key);
    var k = new Uint8Array(64);
    k.set(key);
    var inner = new Uint8Array(64 + msg.length), outer = new Uint8Array(96), i;
    for (i = 0; i < 64; i++) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
    inner.set(msg, 64);
    outer.set(sha256(inner), 64);
    return sha256(outer);
  }

  /* --------------------------------------------------------------- PBKDF2 */
  function pbkdf2(pass, salt, iterations, dkLen) {
    var out = new Uint8Array(dkLen), blocks = Math.ceil(dkLen / 32), i, j, q;
    for (i = 1; i <= blocks; i++) {
      var b = new Uint8Array(salt.length + 4);
      b.set(salt);
      b[salt.length] = (i >>> 24) & 255; b[salt.length + 1] = (i >>> 16) & 255;
      b[salt.length + 2] = (i >>> 8) & 255; b[salt.length + 3] = i & 255;
      var u = hmac(pass, b), t = new Uint8Array(u);
      for (j = 1; j < iterations; j++) {
        u = hmac(pass, u);
        for (q = 0; q < 32; q++) t[q] ^= u[q];
      }
      var take = Math.min(32, dkLen - (i - 1) * 32);
      for (q = 0; q < take; q++) out[(i - 1) * 32 + q] = t[q];
    }
    return out;
  }

  /* ------------------------------------------------------------------ AES */
  var SBOX = new Uint8Array(256), RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  (function buildSbox() {
    var p = 1, q = 1, i, x;
    do {
      p = (p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0)) & 0xff;
      q = (q ^ (q << 1)) & 0xff;
      q = (q ^ (q << 2)) & 0xff;
      q = (q ^ (q << 4)) & 0xff;
      if (q & 0x80) q ^= 0x09;
      x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
        ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
      SBOX[p] = (x ^ 0x63) & 0xff;
    } while (p !== 1);
    SBOX[0] = 0x63;
    for (i = 0; i < 256; i++) { /* force table build order */ }
  })();

  function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }

  function expandKey(key) {
    var Nk = key.length / 4, Nr = Nk + 6;
    var w = new Uint8Array(16 * (Nr + 1));
    var i;
    w.set(key.subarray(0, 4 * Nk));
    for (i = Nk; i < 4 * (Nr + 1); i++) {
      var o = i * 4, p = o - 4;
      var t0 = w[p], t1 = w[p + 1], t2 = w[p + 2], t3 = w[p + 3];
      if (i % Nk === 0) {
        var tmp = t0;
        t0 = SBOX[t1] ^ RCON[(i / Nk) - 1];
        t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp];
      } else if (Nk > 6 && i % Nk === 4) {
        t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
      }
      w[o] = w[o - 4 * Nk] ^ t0;
      w[o + 1] = w[o - 4 * Nk + 1] ^ t1;
      w[o + 2] = w[o - 4 * Nk + 2] ^ t2;
      w[o + 3] = w[o - 4 * Nk + 3] ^ t3;
    }
    return { w: w, Nr: Nr };
  }

  function encryptBlock(ks, s) {
    var w = ks.w, Nr = ks.Nr, r, i, t, o, tmp;
    for (i = 0; i < 16; i++) s[i] ^= w[i];
    for (r = 1; r <= Nr; r++) {
      for (i = 0; i < 16; i++) s[i] = SBOX[s[i]];                       /* SubBytes */
      tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;   /* ShiftRows */
      tmp = s[2]; s[2] = s[10]; s[10] = tmp;
      tmp = s[6]; s[6] = s[14]; s[14] = tmp;
      tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
      if (r !== Nr) {                                                   /* MixColumns */
        for (i = 0; i < 4; i++) {
          o = i * 4;
          var a0 = s[o], a1 = s[o + 1], a2 = s[o + 2], a3 = s[o + 3];
          var all = a0 ^ a1 ^ a2 ^ a3;
          s[o] = a0 ^ all ^ xtime(a0 ^ a1);
          s[o + 1] = a1 ^ all ^ xtime(a1 ^ a2);
          s[o + 2] = a2 ^ all ^ xtime(a2 ^ a3);
          s[o + 3] = a3 ^ all ^ xtime(a3 ^ a0);
        }
      }
      t = r * 16;
      for (i = 0; i < 16; i++) s[i] ^= w[t + i];                        /* AddRoundKey */
    }
  }

  /* ------------------------------------------------------------------ GCM */
  function gfMul(X, H) {
    var Z = new Uint8Array(16), V = new Uint8Array(16), i, j, lsb;
    V.set(H);
    for (i = 0; i < 128; i++) {
      if ((X[i >> 3] >> (7 - (i & 7))) & 1) {
        for (j = 0; j < 16; j++) Z[j] ^= V[j];
      }
      lsb = V[15] & 1;
      for (j = 15; j > 0; j--) V[j] = ((V[j] >> 1) | ((V[j - 1] & 1) << 7)) & 255;
      V[0] = (V[0] >> 1) & 255;
      if (lsb) V[0] ^= 0xe1;
    }
    X.set(Z);
  }

  function gh(H, data) {
    var X = new Uint8Array(16), i, j;
    for (i = 0; i < data.length; i += 16) {
      for (j = 0; j < 16; j++) X[j] ^= data[i + j];
      gfMul(X, H);
    }
    return X;
  }

  function ghash(H, aad, ct) {
    var ab = ((aad.length + 15) >> 4) << 4;
    var cb = ((ct.length + 15) >> 4) << 4;
    var data = new Uint8Array(ab + cb + 16);
    data.set(aad);
    data.set(ct, ab);
    var at = ab + cb;
    var aBits = aad.length * 8, cBits = ct.length * 8;
    data[at] = (aBits >>> 24) & 255; data[at + 1] = (aBits >>> 16) & 255;
    data[at + 2] = (aBits >>> 8) & 255; data[at + 3] = aBits & 255;
    data[at + 12] = (cBits >>> 24) & 255; data[at + 13] = (cBits >>> 16) & 255;
    data[at + 14] = (cBits >>> 8) & 255; data[at + 15] = cBits & 255;
    return gh(H, data);
  }

  /** counter-mode stream starting at counter=2 (12-byte IV GCM) */
  function gctr(ks, iv, input) {
    var out = new Uint8Array(input.length), blk = new Uint8Array(16), n, i, c;
    for (n = 0; n * 16 < input.length; n++) {
      blk.set(iv, 0);
      c = (2 + n) >>> 0;
      blk[12] = (c >>> 24) & 255; blk[13] = (c >>> 16) & 255;
      blk[14] = (c >>> 8) & 255; blk[15] = c & 255;
      encryptBlock(ks, blk);
      for (i = 0; i < 16 && n * 16 + i < input.length; i++) {
        out[n * 16 + i] = input[n * 16 + i] ^ blk[i];
      }
    }
    return out;
  }

  /** AES-256-GCM open.  ctAndTag = ciphertext || 16-byte tag, 12-byte IV. */
  function gcmOpen(key, iv, ctAndTag) {
    var ct = ctAndTag.subarray(0, ctAndTag.length - 16);
    var tag = ctAndTag.subarray(ctAndTag.length - 16);
    var ks = expandKey(key);
    var H = new Uint8Array(16);
    encryptBlock(ks, H);
    var S = ghash(H, new Uint8Array(0), ct);
    var J0 = new Uint8Array(16);
    J0.set(iv);
    J0[15] = 1;
    encryptBlock(ks, J0);
    var diff = 0, i;
    for (i = 0; i < 16; i++) diff |= (S[i] ^ J0[i]) ^ tag[i];
    if (diff !== 0) throw new Error('auth');
    return gctr(ks, iv, ct);
  }

  W.GVH_SOFT = { sha256: sha256, hmac: hmac, pbkdf2: pbkdf2, gcmOpen: gcmOpen };
})(typeof window !== 'undefined' ? window : this);
