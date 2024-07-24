<?php

namespace Morisawa\Auth\Facades;

use Illuminate\Support\Facades\Facade;

class MinoAuth extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'mino-auth';
    }

    public static function guard($name)
    {
        $guards = static::getFacadeRoot();
        return isset($guards[$name]) ? $guards[$name] : null;
    }
}
