<?php
/*
 * @Author: もりさわかな
 * @LastEditTime: 2026-07-22 08:37:16
 */

namespace Morisawa\Auth;

use Illuminate\Support\ServiceProvider;
use Morisawa\Auth\Console\GenerateToken;
use Morisawa\Auth\Guards\MinoGuard;

class MinoAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->publishes([
            __DIR__.'/resources/config/kaede.php' => config_path('kaede.php'),
        ]);
        $this->mergeConfigFrom(__DIR__.'/resources/config/kaede.php', 'kaede');

        $this->app['auth']->extend('mino', function ($app, $name, array $config) {
            $provider = $app['auth']->createUserProvider($config['provider']);
            $request = $app['request'];

            return new MinoGuard($provider, $request, $name);
        });

        $this->app->singleton('mino-auth', function ($app) {
            $guards = config('auth.guards');
            $boundGuards = [];
            foreach ($guards as $name => $config) {
                if ($config['driver'] === 'mino') {
                    $boundGuards[$name] = $app['auth']->guard($name);
                }
            }

            return $boundGuards;
        });
    }

    public function register()
    {
        $this->commands([
            GenerateToken::class,
        ]);
    }
}
