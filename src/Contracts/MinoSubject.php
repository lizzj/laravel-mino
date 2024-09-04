<?php

namespace Morisawa\Auth\Contracts;

interface MinoSubject
{
    public function getBanned(): bool;

    public function getSso($sso_hash): bool;
}
