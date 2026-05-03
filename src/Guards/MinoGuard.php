<?php

namespace Morisawa\Auth\Guards;

use Carbon\Carbon;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Morisawa\Auth\Contracts\MinoSubject;
use Morisawa\Auth\Encryption\Suzume;

class MinoGuard implements Guard
{
    protected $name;

    protected $request;

    protected $provider;

    protected $authId;

    protected $exp = 0;

    const ACCESS_DENIED = 'Access denied:Invalid Authorization.';

    const ACCESS_BANNED = 'Access banned:The account has been banned.';

    const ACCESS_EXPIRED = 'Access expired:Token has expired.';

    const ACCESS_CONFLICT = 'Access conflict:The account has been logged in from another device.';

    public function __construct(UserProvider $provider, Request $request, string $name)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->name = $name;
    }

    public function setExpire($ttlType = 'temporary')
    {
        $ttl = data_get(config('kaede.expire_ttl'), $ttlType, 2);
        $this->exp = Carbon::now()->addHours($ttl)->getTimestamp();

        return $this;
    }

    public function user()
    {
        if ($this->authId !== null) {
            return $this->authId;
        }
        $token = $this->request->bearerToken();
        if ($token) {
            return $this->authId = $this->parseToken($token);
        }
        throw new AuthenticationException(self::ACCESS_DENIED);
    }

    public function id()
    {
        return $this->user();
    }

    public function check()
    {
        try {
            return $this->user() !== null;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function guest()
    {
        return ! $this->check();
    }

    public function setUserId($id)
    {
        $this->authId = $id;

        return $this;
    }

    public function hasUserId()
    {
        return $this->authId !== null;
    }

    public function hasUser()
    {
        return $this->authId !== null;
    }

    public function setUser(Authenticatable $user)
    {
        $this->authId = $user->getAuthIdentifier();
    }

    public function attempt(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user && $this->hasValidCredentials($user, $credentials)) {
            return $this->generateToken($user);
        }

        throw new AuthenticationException(self::ACCESS_DENIED);
    }

    protected function hasValidCredentials($user, $credentials)
    {
        return $this->provider->validateCredentials($user, $credentials);
    }

    public function generateToken(Authenticatable $user)
    {
        if ($this->exp === 0) {
            $this->setExpire();
        }
        if (! $user instanceof MinoSubject) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }

        if (config('kaede.banned_enabled', true) && $user->getBanned()) {
            throw new AuthenticationException(self::ACCESS_BANNED);
        }

        $hash_value = dechex(Carbon::now()->getPreciseTimestamp(6));
        $user->sso_hash = $hash_value;
        $user->save();

        MinoVault::sync($this->name, $user->getAuthIdentifier(), $hash_value, (bool) $user->getBanned(), $this->exp);

        return $this->buildToken($user->getAuthIdentifier(), get_class($user), $hash_value);
    }

    public function refreshToken($userId)
    {
        if ($this->exp === 0) {
            $this->setExpire();
        }
        $user = $this->provider->retrieveById($userId);

        if (! $user || ! $user instanceof MinoSubject) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }

        if (config('kaede.banned_enabled', true) && $user->getBanned()) {
            throw new AuthenticationException(self::ACCESS_BANNED);
        }

        MinoVault::sync($this->name, $user->getAuthIdentifier(), $user->sso_hash, (bool) $user->getBanned(), $this->exp);

        return $this->buildToken($user->getAuthIdentifier(), get_class($user), $user->sso_hash);
    }

    protected function buildToken($id, $modelClass, $hash)
    {
        $payload = [
            'id' => $id,
            'model' => hash('sha3-256', $modelClass),
            'exp' => $this->exp,
            'hash' => $hash,
        ];
        $keys = array_keys($payload);
        shuffle($keys);
        $shuffled = [];
        foreach ($keys as $key) {
            $shuffled[$key] = $payload[$key];
        }

        return Suzume::encrypt($shuffled);
    }

    public function parseToken($token)
    {
        try {
            $payload = Suzume::decrypt($token);
            if (! $payload) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            $cache = MinoVault::get($this->name, $payload['id']);
            if ($cache) {
                $this->validateState($cache['hash'], $payload['hash'], $cache['banned'], $cache['exp']);

                return (int) $payload['id'];
            }
            $user = $this->provider->retrieveById($payload['id']);
            if (! $user || ! $user instanceof MinoSubject) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            if ($payload['model'] !== hash('sha3-256', get_class($user))) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            $this->validateState($user->sso_hash, $payload['hash'], $user->getBanned(), $payload['exp']);
            MinoVault::sync($this->name, $user->getAuthIdentifier(), $user->sso_hash, (bool) $user->getBanned(), $payload['exp']);

            return (int) $user->id;
        } catch (\Exception $e) {
            if ($e instanceof AuthenticationException) {
                throw $e;
            }
            throw new AuthenticationException($e->getMessage());
        }
    }

    protected function validateState($currentHash, $tokenHash, $isBanned, $expireTime)
    {
        if (config('kaede.banned_enabled', true) && $isBanned) {
            throw new AuthenticationException(self::ACCESS_BANNED);
        }
        if (config('kaede.sso_enabled', true) && $currentHash !== $tokenHash) {
            throw new AuthenticationException(self::ACCESS_CONFLICT);
        }
        if (time() > $expireTime) {
            throw new AuthenticationException(self::ACCESS_EXPIRED);
        }
    }

    public function validate(array $credentials = [])
    {
        if (isset($credentials['token'])) {
            try {
                $id = $this->parseToken($credentials['token']);
                $this->setUserId($id);

                return $id !== null;
            } catch (\Exception $e) {
                return false;
            }
        }

        return false;
    }
}
