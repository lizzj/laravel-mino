<?php
namespace Morisawa\Auth\Contracts;

interface MinoSubject
{
   public function getBlock(): bool;
   public function getSso($sso_hash): bool;
}
