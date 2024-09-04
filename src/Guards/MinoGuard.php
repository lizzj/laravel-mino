<?php

namespace Morisawa\Auth\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use Morisawa\Auth\Encryption\Suzume;
use Morisawa\Auth\Contracts\MinoSubject;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Carbon\Carbon;

class MinoGuard implements Guard
{
    protected $request;
    protected $provider;
    protected $user;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    protected $exp = 0; // 默认过期时间

    public function setExpire($ttlType = false)
    {
        $this->exp = match ($ttlType) {
            '-1' => Carbon::now()->addYears(1)->getTimestamp(), // 长期有效（10年）
            '1' => Carbon::now()->addDays(7)->getTimestamp(),       // 7天
            '0' => Carbon::now()->addDay()->getTimestamp(),          // 1天
            default => Carbon::now()->addHours(2)->getTimestamp()       // 默认2小时
        };
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
                throw new AuthenticationException($e->getMessage());
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
                throw new AuthenticationException($e->getMessage());
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
            throw new AuthenticationException('User not found.');
        }
        return $this->generateToken($user);
    }

    public function attempt(array $credentials = [])
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        if ($user && $this->hasValidCredentials($user, $credentials)) {
            return $this->generateToken($user);
        }
        throw new AuthenticationException('Unauthenticated.');
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
            throw new AuthenticationException('User does not implement MinoSubject.');
        }
        $modelClass = $this->provider->getModel();
        if (get_class($user) !== $modelClass) {
            throw new AuthenticationException('User model does not match.');
        }
        $hash_value = dechex(Carbon::now()->getPreciseTimestamp(6));
        $user->sso_hash = $hash_value;
        $user->save();
        $payload = [
            'id' => $user->getAuthIdentifier(),
            'model' => hash('sha256', $modelClass),
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
            throw new AuthenticationException('Token generation failed.');
        }
    }

    public function parseToken($token)
    {
        try {
            $payload = json_decode(Suzume::decrypt($token), true);
            if (!$payload) {
                throw new AuthenticationException('Invalid Authorization.');
            }
            $user = $this->provider->retrieveById($payload['id']);
            if (!$user instanceof MinoSubject) {
                throw new AuthenticationException('User does not implement MinoSubject.');
            }
            if ($user === null) {
                throw new AuthenticationException('User not found.');
            }
            if ($user->getBanned()) {
                throw new AuthenticationException('User is banned.');
            }
            if ($user->getSso($payload['hash'])) {
                throw new AuthenticationException('The account has been logged in to another device.');
            }
            if ($payload['model'] !== hash('sha256', get_class($user))) {
                throw new AuthenticationException('Model mismatch.');
            }
            if (time() > $payload['exp']) {
                throw new AuthenticationException('Token expired.');
            }
            return $payload;
        } catch (\Exception $e) {
            throw new AuthenticationException('Invalid Authorization.');
        }
    }
}
