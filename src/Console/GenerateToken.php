<?php

namespace Morisawa\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;

class GenerateToken extends Command
{
    protected $signature = 'mino:secret {--force : Override existing secret key}';
    protected $description = 'Set the MinoAuth secret key used to sign the tokens';

    public function handle()
    {
        $key = Str::random(16);
        $path = $this->envPath();
        try {
            if (!file_exists($path)) {
                $this->createEnvFile($path, $key);
            } else {
                $this->updateEnvFile($path, $key);
            }
            $this->displayKey($key);
        } catch (\Exception $e) {
            $this->error('An error occurred: '.$e->getMessage());
        }
    }

    protected function createEnvFile($path, $key)
    {
        file_put_contents($path, "MINO_SECRET=$key".PHP_EOL);
        $this->info('Created .env file and set the secret key.');
    }
    protected function updateEnvFile($path, $key)
    {
        $contents = file_get_contents($path);
        if (preg_match('/^MINO_SECRET=.+$/m', $contents)) {
            if (!$this->option('force') && !$this->isConfirmed()) {
                $this->comment('Phew... No changes were made to your secret key.');
                return;
            }
            $contents = preg_replace('/^MINO_SECRET=.*/m', 'MINO_SECRET='.$key, $contents);
        } else {
            $contents .= PHP_EOL."MINO_SECRET=$key";
        }

        file_put_contents($path, $contents);
        $this->info('Updated .env file with the new secret key.');
    }

    protected function displayKey($key)
    {
        $this->info("Mino secret [$key] set successfully.");
    }

    protected function isConfirmed()
    {
        return $this->confirm(
            'This will invalidate all existing tokens. Are you sure you want to override the secret key?'
        );
    }

    protected function envPath()
    {
        return $this->laravel->basePath('.env');
    }
}
