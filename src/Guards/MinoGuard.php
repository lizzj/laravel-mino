<?php

namespace Morisawa\Auth\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Authenticatable;
use Morisawa\Auth\Encryption\Suzume;
use Morisawa\Auth\Contracts\MinoSubject;

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
                throw new AuthenticationException('Invalid or expired token.');
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
                throw new AuthenticationException('Invalid or expired token.');
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

    public function generateToken(Authenticatable $user)
    {
        if (!$user instanceof MinoSubject) {
            throw new AuthenticationException('User does not implement MinoSubject.');
        }
        $modelClass = $this->provider->getModel();
        if (get_class($user) !== $modelClass) {
            throw new AuthenticationException('User model does not match.');
        }

        $payload = [
            'id' => $user->getAuthIdentifier(),
            'model' => hash('sha256', $modelClass),
            'exp' => time() + 3600,
        ];

        try {
            $token = Suzume::encrypt(json_encode($payload));
            return $token;
        } catch (\Exception $e) {
            throw new AuthenticationException('Token generation failed.');
        }
    }

    public function parseToken($token)
    {
        try {
            $payload = json_decode(Suzume::decrypt($token), true);

            if (!$payload) {
                throw new AuthenticationException('Invalid token payload.');
            }
            $user = $this->provider->retrieveById($payload['id']);
            if (!$user instanceof MinoSubject) {
                throw new AuthenticationException('User does not implement MinoSubject.');
            }
            if ($user === null) {
                throw new AuthenticationException('User not found.');
            }

            if ($user->getBlock()) {
                throw new AuthenticationException('User is blocked.');
            }
            if ($payload['model'] !== hash('sha256', get_class($user))) {
                throw new AuthenticationException('Model mismatch.');
            }
            if ($payload['exp'] < time()) {
                throw new AuthenticationException('Token expired.');
            }
            return $payload;
        } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
            throw new AuthenticationException('Token decryption failed.');
        } catch (\Exception $e) {
            throw new AuthenticationException('Token parsing failed.');
        }
    }
}
