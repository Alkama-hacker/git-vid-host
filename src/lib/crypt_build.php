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
