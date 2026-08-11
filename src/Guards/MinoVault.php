<?php

namespace Morisawa\Auth\Guards;

use Illuminate\Support\Facades\Redis;

class MinoVault
{
    public const PER_HASH = 200;

    private static function redis()
    {
        return Redis::connection(config('kaede.cache.database', 'default'));
    }

    protected static function getVaultKey(string $scope, int $id): string
    {
        $index = (int) (($id - 1) / self::PER_HASH) + 1;

        return "mino_auth:{$scope}:{$index}";
    }

    public static function sync(string $scope, int $id, string $hash, bool $isBanned, int $exp): void
    {
        $key = self::getVaultKey($scope, $id);
        $value = "{$hash}:".($isBanned ? '1' : '0').":{$exp}";
        $redis = self::redis();
        $redis->command('HSET', [$key, (string) $id, $value]);
        $redis->expire($key, config('kaede.cache.expire', 86400 * 7));
    }

    public static function get(string $scope, int $id): ?array
    {
        $raw = self::redis()->command('HGET', [self::getVaultKey($scope, $id), $id]);
        if (! $raw) {
            return null;
        }
        $parts = explode(':', $raw);
        if (count($parts) !== 3) {
            return null;
        }

        return [
            'hash' => $parts[0],
            'banned' => $parts[1] === '1',
            'exp' => (int) $parts[2],
        ];
    }

    public static function purge(string $scope, int $id): void
    {
        self::redis()->command('HDEL', [self::getVaultKey($scope, $id), $id]);
    }
}
