<?php

/**
 * @Note
 *
 * @Author Je t'aime
 *
 * @Time 2024/12/17 9:34
 */

namespace Morisawa\Auth\Encryption;

class Hmac
{
    public static string $HASH_HMAC;

    public static function initialize()
    {
        self::$HASH_HMAC = config('kaede.sign');
    }

    public static function generateSign($string): string
    {
        self::initialize();

        return $string.hash_hmac('sha3-256', $string, self::$HASH_HMAC);
    }

    public static function verifySign($originalData, $hashValue): bool
    {
        self::initialize();
        // 重新生成哈希值
        $calculatedHash = hash_hmac('sha3-256', $originalData, self::$HASH_HMAC);

        // 使用 hash_equals 进行安全校验
        return hash_equals($hashValue, $calculatedHash);
    }
}
