<?php

/*
 * @Author: もりさわかな
 * @LastEditTime: 2026-05-06 11:18:37
 */

/*
|--------------------------------------------------------------------------
| Morisawa Auth Config
|--------------------------------------------------------------------------
*/
return [
    // Define different expiration times (in hours)
    'expire_ttl' => [
        'always' => 365 * 24, // Permanent, valid for 365 days
        'medium' => 30 * 24,  // Medium validity, valid for 30 days
        'short' => 7 * 24,    // Short validity, valid for 7 days
        'temporary' => 2,     // Temporary validity, valid for 2 hours
    ],

    // redis cache database
    'cache' => [
        'database'=>'default',
        'expire'=> 7 * 24 * 3600
    ],

    // Hash-based signature key for verification
    'sign' => env('MINO_HASH_SIGN'),

    // Ban feature toggle
    'banned_enabled' => true, // Enable or disable ban feature

    // Single Sign-On (SSO) feature toggle
    'sso_enabled' => true, // Enable or disable SSO feature

    // SM4 encryption configuration
    'SM4' => [
        'SM4_KEY' => env('MINO_SM4_SECRET'),  // SM4 encryption key, retrieved from environment variable, must be 16 characters

        // SM4 encryption MODE,default CBC
        'SM4_MODE' => 'CBC',  // ECB
    ],
];
