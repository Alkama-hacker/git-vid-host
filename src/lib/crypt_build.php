<?php
/**
 * GVH :: build-time cryptography helper (PHP CLI).
 *
 * All primitives that the browser must be able to undo are implemented here so
 * that exactly one code base defines the wire format.  The Python CLI only
 * orchestrates and never needs an AES implementation of its own.
 *
 * Input : JSON file  ($argv[1])
 * Output: JSON file  ($argv[2])
 *
 * Requires: PHP >= 7.1, openssl, zlib, hash.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

define('GVH_VM_MASK', 0xFFFFFFFF);
define('GVH_KEY_CHARS', 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&()*+-./:;<=>?@[]^_{|}~');

function gvh_fail($msg)
{
    if (defined('STDERR')) {
        fwrite(STDERR, "gvh-crypt: " . $msg . "\n");
    }
    if (!empty($GLOBALS['GVH_OUT'])) {
        @file_put_contents($GLOBALS['GVH_OUT'], json_encode(array('ok' => false, 'error' => $msg)));
    }
    exit(2);
}

function gvh_u32($v)
{
    return $v & GVH_VM_MASK;
}

function gvh_mul32($a, $b)
{
    $al = $a & 0xFFFF;
    $ah = ($a >> 16) & 0xFFFF;
    $bl = $b & 0xFFFF;
    $bh = ($b >> 16) & 0xFFFF;
    $lo = $al * $bl;
    $mid = $al * $bh + $ah * $bl;
    return gvh_u32($lo + (($mid & 0xFFFF) << 16));
}

function gvh_rotl32($x, $r)
{
    $r = $r & 31;
    if ($r === 0) {
        return gvh_u32($x);
    }
    return gvh_u32(($x << $r) | (($x & GVH_VM_MASK) >> (32 - $r)));
}

/**
 * The "GVH-VM" layer: a tiny random ARX virtual machine that turns the
 * message into a keystream.  Encrypt and decrypt are the same operation.
 */
function gvh_vm_xor($data, $key, $nonce, array $prog, $rounds)
{
    if ($data === '') {
        return '';
    }
    $seed = hash('sha256', $key . $nonce, true);
    $s = array_values(unpack('V8', $seed));
    $plen = count($prog);
    $out = '';
    $len = strlen($data);
    $blocks = (int) ceil($len / 32);
    $data .= str_repeat("\0", $blocks * 32 - $len);
    for ($n = 0; $n < $blocks; $n++) {
        $s[0] = gvh_u32($s[0] ^ $n);
        $s[6] = gvh_u32($s[6] + $n);
        for ($r = 0; $r < $rounds; $r++) {
            for ($p = 0; $p < $plen; $p++) {
                $ins = $prog[$p];
                $op = $ins & 7;
                $a = ($ins >> 3) & 7;
                $b = ($ins >> 6) & 7;
                switch ($op) {
                    case 0:
                        $s[$a] = gvh_u32($s[$a] + $s[$b]);
                        break;
                    case 1:
                        $s[$a] = gvh_u32($s[$a] ^ $s[$b]);
                        break;
                    case 2:
                        $s[$a] = gvh_rotl32($s[$a], 1 + ($b % 31));
                        break;
                    case 3:
                        $s[$a] = gvh_mul32($s[$a], gvh_u32(2 * $s[$b] + 1));
                        break;
                    case 4:
                        $tmp = $s[$a];
                        $s[$a] = $s[$b];
                        $s[$b] = $tmp;
                        break;
                    case 5:
                        $s[$a] = gvh_u32($s[$a] + 0x9E3779B9 + $n);
                        break;
                    case 6:
                        $s[$a] = gvh_u32($s[$a] ^ ($n * 0x85EBCA6B));
                        break;
                    default:
                        $s[$a] = gvh_u32($s[$a] + ($s[($a + 1) & 7] ^ $n));
                        break;
                }
            }
        }
        $word = pack('V8', $s[0], $s[1], $s[2], $s[3], $s[4], $s[5], $s[6], $s[7]);
        $block = substr($data, $n * 32, 32);
        $out .= $block ^ $word;
    }
    return substr($out, 0, $len);
}

function gvh_vm_program($count)
{
    $prog = array();
    for ($i = 0; $i < $count; $i++) {
        $op = random_int(0, 7);
        $a = random_int(0, 7);
        $b = random_int(0, 7);
        $prog[] = $op | ($a << 3) | ($b << 6);
    }
    return $prog;
}

function gvh_pack_prog(array $prog)
{
    $bin = '';
    foreach ($prog as $ins) {
        $bin .= pack('v', $ins);
    }
    return base64_encode($bin);
}

function gvh_key50()
{
    $chars = GVH_KEY_CHARS;
    $max = strlen($chars) - 1;
    $out = '';
    for ($i = 0; $i < 50; $i++) {
        $out .= $chars[random_int(0, $max)];
    }
    return $out;
}

function gvh_derived_key($str)
{
    return hash('sha256', $str, true);
}

/** AES-256-GCM; returns [ct, tag] */
function gvh_gcm_enc($plain, $key32, $iv)
{
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) {
        gvh_fail('openssl aes-256-gcm failed (extension missing?)');
    }
    return array($ct, $tag);
}

function gvh_content_chunks($b64, $chunkSize)
{
    $len = strlen($b64);
    $chunks = array();
    $pos = 0;
    $idx = 0;
    while ($pos < $len) {
        $take = $chunkSize;
        // keep every slice aligned on a base64 quartet so the browser can
        // atob() each fragment independently.
        if ($take % 4 !== 0) {
            $take -= $take % 4;
        }
        if ($take < 4) {
            $take = 4;
        }
        $piece = substr($b64, $pos, $take);
        $pos += $take;
        $key = gvh_key50();
        $iv = random_bytes(12);
        list($ct, $tag) = gvh_gcm_enc($piece, gvh_derived_key($key), $iv);
        $chunks[] = array(
            'i' => $idx,
            'k' => base64_encode($key),
            'iv' => base64_encode($iv),
            'ct' => base64_encode($ct),
            'tg' => base64_encode($tag),
            'len' => strlen($piece),
        );
        $idx++;
    }
    return $chunks;
}

/**
 * Multi-layer client-side obfuscation envelope:
 *   source -> base64 -> N chunks -> AES-256-GCM (per chunk key)
 *          -> binary -> reversed -> PBKDF2-SHA256 + AES-GCM
 *          -> GVH-VM layer -> base64
 */
function gvh_bundle($source, array $opt)
{
    $nchunks = isset($opt['chunks']) ? (int) $opt['chunks'] : 50;
    $iter = isset($opt['iter']) ? (int) $opt['iter'] : 120000;
    $rounds = isset($opt['vmRounds']) ? (int) $opt['vmRounds'] : 2;
    $progCount = isset($opt['vmProg']) ? (int) $opt['vmProg'] : 96;

    $b64 = base64_encode($source);
    $len = strlen($b64);
    $salt = random_bytes(16);
    $passStr = $opt['core'] . '|' . $opt['site'] . '|' . base64_encode($salt) . '|' . $opt['banner'];
    if ($nchunks < 1) {
        $nchunks = 1;
    }
    if ($nchunks > $len) {
        $nchunks = max(1, $len);
    }
    $size = (int) ceil($len / $nchunks);
    // keep chunk sizes aligned to 4 characters (base64 quartets) and make sure
    // the 50 pieces always cover the whole payload (no trailing remainder)
    $size = (int) (ceil($size / 4) * 4);
    while ($size * $nchunks < $len) {
        $size += 4;
    }
    if ($size < 4) {
        $size = 4;
    }

    $records = array();
    $manifest = array();
    $pos = 0;
    for ($i = 0; $i < $nchunks; $i++) {
        $piece = substr($b64, $pos, $size);
        $pos += $size;
        if ($piece === '') {
            break;
        }
        $key = gvh_key50();
        $iv = random_bytes(12);
        list($ct, $tag) = gvh_gcm_enc($piece, gvh_derived_key($key), $iv);
        $records[] = pack('V', strlen($piece)) . pack('V', strlen($ct)) . $iv . $tag . $ct;
        $manifest[] = array('k' => base64_encode($key), 'iv' => base64_encode($iv));
    }
    $header = 'GVH1' . pack('v', count($records)) . pack('V', $len);
    $inner = $header;
    foreach ($records as $rec) {
        $inner .= $rec;
    }

    // reverse the byte stream
    $reversed = strrev($inner);

    // outer PBKDF2-SHA256 + AES-256-GCM
    $ivOuter = random_bytes(12);
    $pass = hash('sha256', $passStr, true);
    $okm = hash_pbkdf2('sha256', $pass, $salt, $iter, 32, true);
    list($ctOuter, $tagOuter) = gvh_gcm_enc($reversed, $okm, $ivOuter);
    $outer = $salt . $ivOuter . $tagOuter . $ctOuter;

    // GVH-VM layer
    $vmKey = random_bytes(32);
    $vmNonce = random_bytes(16);
    $prog = gvh_vm_program($progCount);
    $vm = gvh_vm_xor($outer, $vmKey, $vmNonce, $prog, $rounds);
    $blob = base64_encode($vm);

    // self-check: every layer we just wrote must decode again with the keys we
    // ship in the manifest.  A failure here is a build we must not release.
    $back = gvh_vm_xor($vm, $vmKey, $vmNonce, $prog, $rounds);
    if ($back !== $outer) {
        gvh_fail('engine self-check: VM layer does not round-trip');
    }
    $plainBack = openssl_decrypt($ctOuter, 'aes-256-gcm', $okm, OPENSSL_RAW_DATA, $ivOuter, $tagOuter);
    if ($plainBack === false || $plainBack !== $reversed) {
        gvh_fail('engine self-check: outer AES-256-GCM does not round-trip');
    }
    if (strrev($plainBack) !== $inner || substr($inner, 0, 4) !== 'GVH1') {
        gvh_fail('engine self-check: inner engine stream is damaged');
    }

    return array(
        'blob' => $blob,
        'manifest' => array(
            'vm' => array(
                'k' => base64_encode($vmKey),
                'n' => base64_encode($vmNonce),
                'p' => gvh_pack_prog($prog),
                'r' => $rounds,
            ),
            'pbkdf2' => array(
                'salt' => base64_encode($salt),
                'iv' => base64_encode($ivOuter),
                'tag' => base64_encode($tagOuter),
                'iter' => $iter,
            ),
            'chunks' => $manifest,
            'verified' => 1,
            'plainLen' => $len,
            'srcHash' => hash('sha256', $source),
            'srcLen' => strlen($source),
        ),
    );
}

function gvh_asset_ctr($bytes, $key32, $iv16)
{
    $ct = openssl_encrypt($bytes, 'aes-256-ctr', $key32, OPENSSL_RAW_DATA, $iv16);
    if ($ct === false) {
        gvh_fail('openssl aes-256-ctr failed');
    }
    return $ct;
}


/* ------------------------------------------------------------------------- */
/* secure vault (files, folders, zips -> one encrypted container)             */
/* ------------------------------------------------------------------------- */
/**
 * Container layout
 *
 *   "GVHVAULT1\n"                      11-byte magic
 *   uint32 BE  header length
 *   header JSON (see gvh_vault_header)  bound as GCM additional data
 *   for each chunk:
 *       uint32 BE ciphertext length
 *       ciphertext
 *       16-byte GCM tag
 *
 * Key  : PBKDF2-SHA256(password, salt, iter, 32 bytes)
 * IV   : 8 random bytes from the header + uint32 BE chunk index (12 bytes)
 * AAD  : sha256(header JSON) - so the metadata cannot be edited
 */
define('GVH_VAULT_MAGIC', "GVHVAULT1\n");

function gvh_vault_key($password, $salt, $iter)
{
    return hash_pbkdf2('sha256', $password, $salt, (int) $iter, 32, true);
}

function gvh_vault_seal($bytes, $password, $name, $kind, $iter, $chunk)
{
    if ($password === '' || strlen($password) < 4) {
        gvh_fail('vault: the password must be at least 4 characters');
    }
    $salt = random_bytes(16);
    $ivp = random_bytes(8);
    $key = gvh_vault_key($password, $salt, $iter);
    $size = strlen($bytes);
    $n = max(1, (int) ceil($size / $chunk));
    $header = array(
        'v' => 1,
        'name' => $name,
        'kind' => $kind,
        'size' => $size,
        'sha256' => hash('sha256', $bytes),
        'salt' => base64_encode($salt),
        'iv' => base64_encode($ivp),
        'iter' => (int) $iter,
        'chunk' => (int) $chunk,
        'n' => $n,
        'made' => gmdate('c'),
    );
    $hjson = json_encode($header, JSON_UNESCAPED_SLASHES);
    $aad = hash('sha256', $hjson, true);
    $out = GVH_VAULT_MAGIC . pack('N', strlen($hjson)) . $hjson;
    for ($i = 0; $i < $n; $i++) {
        $part = substr($bytes, $i * $chunk, $chunk);
        $iv = $ivp . pack('N', $i);
        $tag = '';
        $ct = openssl_encrypt($part, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if ($ct === false) {
            gvh_fail('vault: AES-256-GCM failed');
        }
        $out .= pack('N', strlen($ct)) . $ct . $tag;
    }
    return array($out, $header);
}

function gvh_vault_header($container)
{
    $magic = strlen(GVH_VAULT_MAGIC);
    if (strlen($container) < $magic + 5 || substr($container, 0, $magic) !== GVH_VAULT_MAGIC) {
        gvh_fail('vault: not a GVH vault file');
    }
    $hl = unpack('N', substr($container, $magic, 4));
    $hl = $hl[1];
    if ($hl < 2 || $hl > 65536 || strlen($container) < $magic + 4 + $hl) {
        gvh_fail('vault: damaged header');
    }
    $hjson = substr($container, $magic + 4, $hl);
    $header = json_decode($hjson, true);
    if (!is_array($header) || !isset($header['n'], $header['salt'], $header['iv'])) {
        gvh_fail('vault: bad header');
    }
    return array($header, $hjson, $magic + 4 + $hl);
}

function gvh_vault_open($container, $password, &$header)
{
    list($header, $hjson, $off) = gvh_vault_header($container);
    $aad = hash('sha256', $hjson, true);
    $key = gvh_vault_key($password, base64_decode($header['salt']), $header['iter']);
    $ivp = base64_decode($header['iv']);
    $out = '';
    $total = strlen($container);
    for ($i = 0; $i < (int) $header['n']; $i++) {
        if ($off + 4 > $total) {
            gvh_fail('vault: truncated (header says ' . $header['n'] . ' chunks)');
        }
        $len = unpack('N', substr($container, $off, 4));
        $len = $len[1];
        $off += 4;
        if ($off + $len + 16 > $total) {
            gvh_fail('vault: truncated chunk ' . $i);
        }
        $ct = substr($container, $off, $len);
        $off += $len;
        $tag = substr($container, $off, 16);
        $off += 16;
        $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $ivp . pack('N', $i), $tag, $aad);
        if ($pt === false) {
            gvh_fail('vault: wrong password or damaged file');
        }
        $out .= $pt;
    }
    if (strlen($out) !== (int) $header['size'] || hash('sha256', $out) !== $header['sha256']) {
        gvh_fail('vault: checksum mismatch');
    }
    return $out;
}

function gvh_cfg_blob($json)
{
    if (function_exists('gzdeflate')) {
        $z = gzdeflate($json, 9);
        if ($z !== false) {
            return 'G1.' . base64_encode($z);
        }
    }
    return 'B1.' . base64_encode($json);
}

/* --------------------------------------------------------------------- */

$inPath = isset($GLOBALS['GVH_IN']) ? $GLOBALS['GVH_IN'] : (isset($argv[1]) ? $argv[1] : '');
$outPath = isset($GLOBALS['GVH_OUT']) ? $GLOBALS['GVH_OUT'] : (isset($argv[2]) ? $argv[2] : '');
$GLOBALS['GVH_OUT'] = $outPath;
if ($inPath === '' || $outPath === '') {
    gvh_fail('usage: crypt_build.php <in.json> <out.json>');
}
$in = json_decode(file_get_contents($inPath), true);
if (!is_array($in)) {
    gvh_fail('bad input json');
}
function gvh_handle($in)
{
    $op = isset($in['op']) ? $in['op'] : '';
    $res = array('ok' => true);
    if ($op === 'bundle') {
        $src = base64_decode($in['source_b64'], true);
        if ($src === false) {
            gvh_fail('source_b64 decode failed');
        }
        $res['bundle'] = gvh_bundle($src, $in);
    } elseif ($op === 'content') {
        $b64 = $in['data_b64'];
        $size = isset($in['chunk_size']) ? (int) $in['chunk_size'] : 16384;
        $res['chunks'] = gvh_content_chunks($b64, $size);
    } elseif ($op === 'asset') {
        $bytes = base64_decode($in['data_b64'], true);
        if ($bytes === false) {
            gvh_fail('asset decode failed');
        }
        $key = random_bytes(32);
        $iv = random_bytes(16);
        $ct = gvh_asset_ctr($bytes, $key, $iv);
        $res['asset'] = array(
            'k' => base64_encode($key),
            'iv' => base64_encode($iv),
            'size' => strlen($bytes),
            'ct_b64' => base64_encode($ct),
        );
    } elseif ($op === 'cfg') {
        $res['cfg'] = gvh_cfg_blob(json_encode($in['cfg'], JSON_UNESCAPED_SLASHES));
    } elseif ($op === 'vm_selftest') {
        $key = str_repeat("\x01", 32);
        $nonce = str_repeat("\x02", 16);
        $prog = array();
        for ($i = 0; $i < 32; $i++) {
            $prog[] = ($i * 7) % 8 | (((3 * $i) % 8) << 3) | (((5 * $i) % 8) << 6);
        }
        $data = '';
        for ($i = 0; $i < 100; $i++) {
            $data .= chr(($i * 37) % 256);
        }
        $enc = gvh_vm_xor($data, $key, $nonce, $prog, 2);
        $res['vm'] = array(
            'key' => base64_encode($key),
            'nonce' => base64_encode($nonce),
            'prog' => gvh_pack_prog($prog),
            'data' => base64_encode($data),
            'enc' => base64_encode($enc),
        );
    } elseif ($op === 'vault_seal' || $op === 'vault_open' || $op === 'vault_info') {
        $iter = isset($in['iter']) ? (int) $in['iter'] : 150000;
        $chunk = isset($in['chunk']) ? (int) $in['chunk'] : 1048576;
        if ($iter < 10000 || $iter > 4000000) {
            gvh_fail('vault: iteration count out of range');
        }
        if ($chunk < 1024 || $chunk > 67108864) {
            gvh_fail('vault: chunk size out of range');
        }
        $isSeal = ($op === 'vault_seal');
        $inPath = isset($in['in_path']) ? $in['in_path'] : '';
        $vaultPath = isset($in['vault_path']) ? $in['vault_path'] : '';
        $outPath = isset($in['out_path']) ? $in['out_path'] : '';
        try {
            if ($op === 'vault_info') {
                if ($vaultPath !== '') {
                    if (!is_file($vaultPath)) {
                        gvh_fail('vault: file not found');
                    }
                    $container = file_get_contents($vaultPath);
                } else {
                    $container = base64_decode((string) $in['vault_b64'], true);
                }
                if ($container === false) {
                    gvh_fail('vault: cannot read container');
                }
                list($header) = gvh_vault_header($container);
                $res['vault'] = array('meta' => $header);
                return $res;
            }
            if ($isSeal) {
                if ($inPath !== '') {
                    if (!is_file($inPath)) {
                        gvh_fail('vault: input file not found');
                    }
                    $bytes = file_get_contents($inPath);
                } else {
                    $bytes = base64_decode((string) $in['data_b64'], true);
                }
                if ($bytes === false) {
                    gvh_fail('vault: cannot read input');
                }
                list($container, $header) = gvh_vault_seal(
                    $bytes,
                    (string) $in['password'],
                    isset($in['name']) ? (string) $in['name'] : 'payload.bin',
                    isset($in['kind']) ? (string) $in['kind'] : 'file',
                    $iter,
                    $chunk
                );
                if ($outPath !== '') {
                    if (file_put_contents($outPath, $container) === false) {
                        gvh_fail('vault: cannot write ' . $outPath);
                    }
                    $res['vault'] = array('meta' => $header, 'bytes' => strlen($container), 'written' => $outPath);
                } else {
                    $res['vault'] = array('meta' => $header, 'bytes' => strlen($container), 'container_b64' => base64_encode($container));
                }
                return $res;
            }
            if ($vaultPath !== '') {
                if (!is_file($vaultPath)) {
                    gvh_fail('vault: file not found');
                }
                $container = file_get_contents($vaultPath);
            } else {
                $container = base64_decode((string) $in['vault_b64'], true);
            }
            if ($container === false) {
                gvh_fail('vault: cannot read container');
            }
            $header = array();
            $bytes = gvh_vault_open($container, (string) $in['password'], $header);
            if ($outPath !== '') {
                file_put_contents($outPath, $bytes);
                $res['vault'] = array('meta' => $header, 'written' => $outPath);
            } else {
                $res['vault'] = array('meta' => $header, 'data_b64' => base64_encode($bytes));
            }
        } catch (Exception $e) {
            gvh_fail('vault: ' . $e->getMessage());
        }
    } elseif ($op === 'batch') {
        $results = array();
        foreach ($in['ops'] as $one) {
            $results[] = gvh_handle($one);
        }
        $res['results'] = $results;
    } elseif ($op === 'ping') {
        $res['pong'] = 'gvh';
    } else {
        gvh_fail('unknown op: ' . $op);
    }
    return $res;
}

$out = gvh_handle($in);
file_put_contents($outPath, json_encode($out, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
