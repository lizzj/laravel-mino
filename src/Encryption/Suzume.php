<?php

namespace Morisawa\Auth\Encryption;

class Suzume
{
    public const SM4_CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
    ];

    public const SM4_SBOX = [
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
    ];

    public const SM4_FK = [
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC,
    ];

    public const BLOCK_SIZE = 16;

    public static array $_rk;

    public static function encrypt(array $data): string
    {
        self::crk();
        $ori_data = http_build_query($data);
        $result = match (config('kaede.SM4.SM4_MODE')) {
            'ECB' => self::encryptEcb($ori_data),
            default => self::encryptCbc($ori_data),
        };

        return Hmac::generateSign(bin2hex($result));
    }

    public static function decrypt($signature): array|false
    {
        $hashValue = substr($signature, -64);
        $originalHex = substr($signature, 0, -64);
        if (! Hmac::verifySign($originalHex, $hashValue)) {
            return false;
        }
        $originalData = hex2bin($originalHex);
        if ($originalData === false) {
            return false;
        }
        $parse_result = match (config('kaede.SM4.SM4_MODE')) {
            'ECB' => self::decryptEcb($originalData),
            default => self::decryptCbc($originalData),
        };
        if ($parse_result) {
            parse_str($parse_result, $result);

            return $result;
        }

        return false;
    }

    // ================= 原生 CBC =================
    private static function encryptCbc($ori_data)
    {
        $iv = random_bytes(self::BLOCK_SIZE);
        $padded = self::pad($ori_data);
        try {
            $cipher = openssl_encrypt($padded, 'SM4-CBC', config('kaede.SM4.SM4_KEY'), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
            if ($cipher === false) {
                $cipher = self::enDataCbc($padded, $iv);
            }
        } catch (\Throwable $e) {
            $cipher = self::enDataCbc($padded, $iv);
        }

        return $iv.$cipher;
    }

    private static function decryptCbc($original)
    {
        $iv = substr($original, 0, self::BLOCK_SIZE);
        $cipher = substr($original, self::BLOCK_SIZE);
        try {
            $ret = openssl_decrypt($cipher, 'SM4-CBC', config('kaede.SM4.SM4_KEY'), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
            if ($ret === false) {
                $ret = self::deDataCbc($cipher, $iv); // fallback 到原生
            }
        } catch (\Throwable $e) {
            $ret = self::deDataCbc($cipher, $iv);
        }
        if (self::isValidPadding($ret)) {
            return self::unpad($ret);
        }

        return false;
    }

    private static function encryptEcb($ori_data)
    {
        $padded = self::pad($ori_data);
        try {
            $cipher = openssl_encrypt($padded, 'SM4-ECB', config('kaede.SM4.SM4_KEY'), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($cipher === false) {
                $cipher = self::enDataEcb($padded);
            }
        } catch (\Throwable $e) {
            $cipher = self::enDataEcb($padded);
        }

        return $cipher;
    }

    private static function decryptEcb($originalData)
    {
        try {
            $ret = openssl_decrypt($originalData, 'SM4-ECB', config('kaede.SM4.SM4_KEY'), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($ret === false) {
                $ret = self::deDataEcb($originalData); // fallback 到原生
            }
        } catch (\Throwable $e) {
            $ret = self::deDataEcb($originalData);
        }
        if (self::isValidPadding($ret)) {
            return self::unpad($ret);
        }

        return false;
    }

    private static function isValidPadding(string $data, int $blockSize = 16): bool
    {
        if (strlen($data) === 0 || strlen($data) % $blockSize !== 0) {
            return false; // 长度不对
        }
        $n = ord($data[strlen($data) - 1]);
        if ($n < 1 || $n > $blockSize) {
            return false;
        }
        $pad = substr($data, -$n);

        return $pad === str_repeat(chr($n), $n);
    }

    // ================= 公共方法 =================
    private static function pad(string $data): string
    {
        $n = self::BLOCK_SIZE - (strlen($data) % self::BLOCK_SIZE);

        return $data.str_repeat(chr($n), $n);
    }

    private static function unpad(string $data): string
    {
        $n = ord(substr($data, -1));

        return substr($data, 0, -$n);
    }

    private static function crk()
    {
        $key = config('kaede.SM4.SM4_KEY');
        $keys = array_values(unpack('N*', $key));
        $keys = [
            $keys[0] ^ self::SM4_FK[0],
            $keys[1] ^ self::SM4_FK[1],
            $keys[2] ^ self::SM4_FK[2],
            $keys[3] ^ self::SM4_FK[3],
        ];
        self::$_rk = [];
        for ($i = 0; $i < 32; $i++) {
            $tmp = $keys[$i + 1] ^ $keys[$i + 2] ^ $keys[$i + 3] ^ self::SM4_CK[$i];
            $keys[] = $keys[$i] ^ self::t1($tmp);
            self::$_rk[$i] = $keys[$i + 4];
        }
    }

    private static function enDataCbc($str, $iv): string
    {
        $r = '';
        $chunks = str_split($str, self::BLOCK_SIZE);
        foreach ($chunks as $chunk) {
            $chunk = $iv ^ $chunk;
            $tr = [];
            self::encode(array_values(unpack('N*', $chunk)), $tr);
            $iv = pack('N*', ...$tr);
            $r .= $iv;
        }

        return $r;
    }

    private static function deDataCbc($cipher, $iv): string
    {
        $r = '';
        $chunks = str_split($cipher, self::BLOCK_SIZE);
        foreach ($chunks as $chunk) {
            $tr = [];
            self::decode(array_values(unpack('N*', $chunk)), $tr);
            $s1 = pack('N*', ...$tr);
            $s1 = $iv ^ $s1;
            $iv = $chunk;
            $r .= $s1;
        }

        return $r;
    }

    private static function enDataEcb($str): string
    {
        $r = '';
        $chunks = str_split($str, self::BLOCK_SIZE);
        foreach ($chunks as $chunk) {
            $tr = [];
            self::encode(array_values(unpack('N*', $chunk)), $tr);
            $r .= pack('N*', ...$tr);
        }

        return $r;
    }

    private static function deDataEcb($str): string
    {
        $r = '';
        $chunks = str_split($str, self::BLOCK_SIZE);
        foreach ($chunks as $chunk) {
            $tr = [];
            self::decode(array_values(unpack('N*', $chunk)), $tr);
            $r .= pack('N*', ...$tr);
        }

        return $r;
    }

    private static function encode($ar, &$r)
    {
        for ($i = 0; $i < 32; $i++) {
            $ar[$i + 4] = self::f($ar[$i], $ar[$i + 1], $ar[$i + 2], $ar[$i + 3], self::$_rk[$i]);
        }
        $r[] = $ar[35];
        $r[] = $ar[34];
        $r[] = $ar[33];
        $r[] = $ar[32];
    }

    private static function decode($ar, &$r)
    {
        for ($i = 0; $i < 32; $i++) {
            $ar[$i + 4] = self::f($ar[$i], $ar[$i + 1], $ar[$i + 2], $ar[$i + 3], self::$_rk[31 - $i]);
        }
        $r[] = $ar[35];
        $r[] = $ar[34];
        $r[] = $ar[33];
        $r[] = $ar[32];
    }

    private static function f($x0, $x1, $x2, $x3, $r)
    {
        return $x0 ^ self::t($x1 ^ $x2 ^ $x3 ^ $r);
    }

    private static function t($n)
    {
        $b = self::SM4_SBOX[$n & 0xFF] | self::SM4_SBOX[($n >> 8) & 0xFF] << 8 | self::SM4_SBOX[($n >> 16) & 0xFF] << 16 | self::SM4_SBOX[($n >> 24) & 0xFF] << 24;

        return $b ^ self::lm($b, 2) ^ self::lm($b, 10) ^ self::lm($b, 18) ^ self::lm($b, 24);
    }

    private static function t1($n)
    {
        $b = self::SM4_SBOX[$n & 0xFF] | self::SM4_SBOX[($n >> 8) & 0xFF] << 8 | self::SM4_SBOX[($n >> 16) & 0xFF] << 16 | self::SM4_SBOX[($n >> 24) & 0xFF] << 24;

        return $b ^ self::lm($b, 13) ^ self::lm($b, 23);
    }

    private static function lm($a, $n)
    {
        return ($a >> (32 - $n)) | (($a << $n) & 0xFFFFFFFF);
    }
}
