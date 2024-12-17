<?php

namespace Morisawa\Auth\Encryption;

use Illuminate\Auth\AuthenticationException;

class Suzume
{
    public static array $SM4_CK;
    public static array $SM4_SBOX;
    public static array $SM4_FK;
    public static string $SM4_KEY;
    public static array $_rk;
    public const BLOCK_SIZE = 16;

    public static function initialize()
    {
        self::$SM4_CK = config("kaede.SM4.SM4_CK");
        self::$SM4_SBOX = config("kaede.SM4.SM4_SBOX");
        self::$SM4_FK = config("kaede.SM4.SM4_FK");
        self::$SM4_KEY = config("kaede.SM4.SM4_KEY");
    }

    public static function encrypt($data): string
    {
        self::initialize();
        self::sM4KeySchedule();
        $bytes = self::pad($data);
        $chunks = array_chunk($bytes, self::BLOCK_SIZE);
        $ciphertext = "";
        foreach ($chunks as $chunk) {
            $ciphertext .= self::sM4Encrypt($chunk);
        }
        return Hmac::generateSign(bin2hex($ciphertext));
    }

    public static function decrypt($signature): bool|string
    {
        self::initialize();
        //先调用hash检测, 判断是否被修改过,提取字符串末尾的 64 位作为哈希值
        $hashValue = substr($signature, -64);
        // 提取剩余部分作为原始数据
        $originalData = substr($signature, 0, -64);
        if (!Hmac::verifySign($originalData, $hashValue)) {
            return false;
        }
        $data = hex2bin($originalData);
        if (strlen($data) % self::BLOCK_SIZE !== 0) {
            return false;
        }
        self::sM4KeySchedule();
        $bytes = unpack("C*", $data);
        $chunks = array_chunk($bytes, self::BLOCK_SIZE);
        $plaintext = "";
        foreach ($chunks as $chunk) {
            $plaintext .= substr(self::sM4Decrypt($chunk), 0, 16);
        }
        return self::un_pad($plaintext);
    }

    private static function sM4Decrypt($cipherText): string
    {
        $x = self::getX($cipherText);
        for ($i = 0; $i < 32; $i++) {
            $tmp = $x[$i + 1] ^ $x[$i + 2] ^ $x[$i + 3] ^ self::$_rk[31 - $i];
            $buf = self::getI($tmp);
            $x[$i + 4] = $x[$i] ^ ($buf ^ self::sm4Rotl32(($buf), 2) ^ self::sm4Rotl32(($buf), 10) ^ self::sm4Rotl32(($buf), 18) ^ self::sm4Rotl32(($buf), 24));
        }
        return self::extracted($x);
    }

    private static function sM4Encrypt($plainText): string
    {
        $x = self::getX($plainText);
        for ($i = 0; $i < 32; $i++) {
            $tmp = $x[$i + 1] ^ $x[$i + 2] ^ $x[$i + 3] ^ self::$_rk[$i];
            $buf = self::getI($tmp);
            $x[$i + 4] = $x[$i] ^ ($buf ^ self::sm4Rotl32(($buf), 2) ^ self::sm4Rotl32(($buf), 10) ^ self::sm4Rotl32(($buf), 18) ^ self::sm4Rotl32(($buf), 24));
        }
        return self::extracted($x);
    }

    private static function stringToBytes($string): bool|array
    {
        return unpack('C*', $string);
    }

    private static function bytesToString($bytes): string
    {
        return vsprintf(str_repeat('%c', count($bytes)), $bytes);
    }

    private static function pad($data): bool|array
    {
        $bytes = self::stringToBytes($data);
        $rem = self::BLOCK_SIZE - count($bytes) % self::BLOCK_SIZE;
        for ($i = 0; $i < $rem; $i++) {
            $bytes[] = $rem;
        }
        return $bytes;
    }

    private static function un_pad($data): string
    {
        $bytes = self::stringToBytes($data);
        $bytes = array_slice($bytes, 0, count($bytes) - $bytes[count($bytes)]);
        return self::bytesToString($bytes);
    }

    private static function sm4Rotl32($buf, $n): int
    {
        return (($buf << $n) & 0xffffffff) | ($buf >> (32 - $n));
    }

    private static function sM4KeySchedule(): void
    {
        $sm4Key = self::$SM4_KEY;
        if (empty($sm4Key) || strlen($sm4Key) !== self::BLOCK_SIZE) {
            throw new \InvalidArgumentException('Invalid key or input length.');
        }
        self::$_rk = [];
        $key = array_values(unpack("C*", $sm4Key));
        $k = [];
        for ($i = 0; $i < 4; $i++) {
            $k[$i] = self::$SM4_FK[$i] ^ (($key[4 * $i] << 24) | ($key[4 * $i + 1] << 16) | ($key[4 * $i + 2] << 8) | ($key[4 * $i + 3]));
        }
        for ($j = 0; $j < 32; $j++) {
            $tmp = $k[$j + 1] ^ $k[$j + 2] ^ $k[$j + 3] ^ self::$SM4_CK[$j];
            $buf = self::getI($tmp);
            $k[$j + 4] = $k[$j] ^ (($buf) ^ (self::sm4Rotl32(($buf), 13)) ^ (self::sm4Rotl32(($buf), 23)));
            self::$_rk[$j] = $k[$j + 4];
        }
    }

    private static function getI(int $tmp): int
    {
        return (self::$SM4_SBOX[($tmp >> 24) & 0xFF]) << 24 | (self::$SM4_SBOX[($tmp >> 16) & 0xFF]) << 16 | (self::$SM4_SBOX[($tmp >> 8) & 0xFF]) << 8 | (self::$SM4_SBOX[$tmp & 0xFF]);
    }

    private static function getX($plainText): array
    {
        $x = [];
        for ($j = 0; $j < 4; $j++) {
            $x[$j] = ($plainText[$j * 4] << 24) | ($plainText[$j * 4 + 1] << 16) | ($plainText[$j * 4 + 2] << 8) | ($plainText[$j * 4 + 3]);
        }
        return $x;
    }

    private static function extracted($x): string
    {
        $cipherText = [];
        for ($k = 0; $k < 4; $k++) {
            $cipherText[4 * $k] = ($x[35 - $k] >> 24) & 0xFF;
            $cipherText[4 * $k + 1] = ($x[35 - $k] >> 16) & 0xFF;
            $cipherText[4 * $k + 2] = ($x[35 - $k] >> 8) & 0xFF;
            $cipherText[4 * $k + 3] = ($x[35 - $k]) & 0xFF;
        }
        return self::bytesToString($cipherText);
    }
}
