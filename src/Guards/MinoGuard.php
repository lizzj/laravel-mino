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
                throw new AuthenticationException('Access denied:Invalid Authorization.');
            }
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
                throw new AuthenticationException('Access denied:Invalid Authorization.');
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
            throw new AuthenticationException('Access denied: Failed to authorize.');
        }

        return $this->generateToken($user);
    }

    public function attempt(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($user && $this->hasValidCredentials($user, $credentials)) {
            return $this->generateToken($user);
        }
        throw new AuthenticationException('Access denied: Authorization error.');
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
            throw new AuthenticationException('Access denied:Authorization error.');
        }
        $modelClass = $this->provider->getModel();
        if (get_class($user) !== $modelClass) {
            throw new AuthenticationException('Access denied:Authorization error.');
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
            throw new AuthenticationException('Access denied: Failed to generate authentication token.');
        }
    }

    public function refreshToken($userId)
    {
        $user = $this->provider->retrieveById($userId);
        if (!$user || !$user instanceof MinoSubject) {
            throw new AuthenticationException('Access denied: Authorization error.');
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
            throw new AuthenticationException('Access denied: Failed to generate authentication token.');
        }
    }

    public function parseToken($token)
    {
        try {
            $payload = json_decode(Suzume::decrypt($token), true);
            if (!$payload) {
                throw new AuthenticationException('Access denied:Authorization error..');
            }
            $user = $this->provider->retrieveById($payload['id']);
            if (!$user instanceof MinoSubject) {
                throw new AuthenticationException('Access denied:Authorization error..');
            }
            if ($user === null) {
                throw new AuthenticationException('Access denied:Invalid Authorization.');
            }
            if (config('kaede.banned_enabled', true) && $user->getBanned()) {
                throw new \App\Exceptions\BannedExceptions('Access invalid:The account has been disabled.');
            }
            if (config('kaede.sso_enabled', true) && $user->getSso($payload['hash'])) {
                throw new AuthenticationException('Access invalid:Account has been logged in from another device.');
            }
            if ($payload['model'] !== hash('sha3-256', get_class($user))) {
                throw new AuthenticationException('Access denied:Invalid Authorization.');
            }
            if (time() > $payload['exp']) {
                throw new AuthenticationException('Access invalid:Token has expired.');
            }

            return $payload;
        } catch (\Exception $e) {
            throw new AuthenticationException('Access denied:Invalid Authorization.');
        }
    }
}
