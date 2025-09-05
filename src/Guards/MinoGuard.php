<?php

namespace Morisawa\Auth\Guards;

use Carbon\Carbon;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Morisawa\Auth\Contracts\MinoSubject;
use Morisawa\Auth\Encryption\Suzume;

class MinoGuard implements Guard
{
    protected $request;

    protected $provider;

    protected $user;

    protected $exp = 0;

    const ACCESS_DENIED = 'Access denied:Invalid Authorization.';

    const ACCESS_BANNED = 'Access banned:The account has been banned.';

    const ACCESS_EXPIRED = 'Access expired:Token has expired.';

    const ACCESS_CONFLICT = 'Access conflict:The account has been logged in from another device.';

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    public function setExpire($ttlType = 'temporary')
    {
        $ttl = data_get(config('kaede.expire_ttl'), $ttlType, 2);
        $this->exp = Carbon::now()->addHours($ttl)->getTimestamp();

        return $this;
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }
        $token = $this->request->bearerToken();
        if ($token) {
            try {
                $payload = $this->parseToken($token);
                $this->user = $this->provider->retrieveById($payload['id']);
            } catch (AuthenticationException $e) {
                throw new AuthenticationException($e->getMessage(), $e->guards());
            }
        } else {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }

        return $this->user;
    }

    public function validate(array $credentials = [])
    {
        if (isset($credentials['token'])) {
            try {
                $payload = $this->parseToken($credentials['token']);
                $this->user = $payload ? $this->provider->retrieveById($payload['id']) : null;

                return $this->user !== null;
            } catch (AuthenticationException $e) {
                throw new AuthenticationException($e->getMessage(), $e->guards());
            }
        }

        return false;
    }

    public function check()
    {
        return $this->user() !== null;
    }

    public function guest()
    {
        return !$this->check();
    }

    public function id()
    {
        $user = $this->user();

        return $user ? $user->getAuthIdentifier() : null;
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

    public function hasUser()
    {
        return $this->user !== null;
    }

    public function tokenById($userId)
    {
        $user = $this->provider->retrieveById($userId);
        if (!$user) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }

        return $this->generateToken($user);
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
        if (!$user instanceof MinoSubject) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }
        $modelClass = $this->provider->getModel();
        if (get_class($user) !== $modelClass) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }
        if (config('kaede.banned_enabled', true) && $user->getBanned()) {
            throw new AuthenticationException(self::ACCESS_BANNED, ['banned' => true]);
        }
        $hash_value = dechex(Carbon::now()->getPreciseTimestamp(6));
        $user->sso_hash = $hash_value;
        $user->save();
        $payload = [
            'id' => $user->getAuthIdentifier(),
            'model' => hash('sha3-256', $modelClass),
            'exp' => $this->exp,
            'hash' => $hash_value,
        ];
        try {
            $shuffle = Arr::shuffle(['id', 'model', 'exp', 'hash']);
            $shuffleArray = [];
            foreach ($shuffle as $item) {
                $shuffleArray[$item] = $payload[$item];
            }

            return Suzume::encrypt(json_encode($shuffleArray));
        } catch (\Exception $e) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }
    }

    public function refreshToken($userId)
    {
        $user = $this->provider->retrieveById($userId);
        if (!$user || !$user instanceof MinoSubject) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }
        $payload = [
            'id' => $user->getAuthIdentifier(),
            'model' => hash('sha3-256', get_class($user)), // 更灵活：防止多模型混用时伪造
            'exp' => $this->setExpire(),
            'hash' => $user->sso_hash,
        ];
        try {
            $shuffle = Arr::shuffle(array_keys($payload));
            $shuffledPayload = [];
            foreach ($shuffle as $key) {
                $shuffledPayload[$key] = $payload[$key];
            }

            return Suzume::encrypt(json_encode($shuffledPayload));
        } catch (\Exception $e) {
            throw new AuthenticationException(self::ACCESS_DENIED);
        }
    }

    public function parseToken($token)
    {
        try {
            $payload = json_decode(Suzume::decrypt($token), true);
            if (!$payload) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            $user = $this->provider->retrieveById($payload['id']);
            if (!$user instanceof MinoSubject) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            if ($user === null) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            if (config('kaede.banned_enabled', true) && $user->getBanned()) {
                throw new AuthenticationException(self::ACCESS_BANNED, ['banned' => true]);
            }
            if (config('kaede.sso_enabled', true) && $user->getSso($payload['hash'])) {
                throw new AuthenticationException(self::ACCESS_CONFLICT);
            }
            if ($payload['model'] !== hash('sha3-256', get_class($user))) {
                throw new AuthenticationException(self::ACCESS_DENIED);
            }
            if (time() > $payload['exp']) {
                throw new AuthenticationException(self::ACCESS_EXPIRED);
            }

            return $payload;
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage(), $e->guards());
        }
    }
}
