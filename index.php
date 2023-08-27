<?php

// 自动加载
require_once './vendor/autoload.php';

use Wuchenge\Jwt\Jwt;

$config = [
    'key'       => 'wuchenge',
    'algorithm' => 'SHA256',
    'issuer'    => 'appWithWuchenge',
    'expire'    => 604800, // 24 * 60 * 60 * 7
];

$payload = [
	'user_id' 	=> 123,
	'user_name' => 'test'
];

$payload = array_merge([
    'iss' => $config['issuer'],
    'iat' => $_SERVER['REQUEST_TIME'],
    'exp' => $_SERVER['REQUEST_TIME'] + $config['expire'],
], $payload);

echo JWT::encode($payload, $config['key'], $config['algorithm']);

$token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJTSEEyNTYifQ.eyJpc3MiOiJhcHBXaXRoV3VjaGVuZ2UiLCJpYXQiOjE2OTMxMzkwNjQsImV4cCI6MTY5Mzc0Mzg2NCwidXNlcl9pZCI6MTIzLCJ1c2VyX25hbWUiOiJ0ZXN0In0.08c94742d0911adff30b77c3b9509d644dcb5d6b0c11c96f3e4ff0734dbecb65';

$payload = JWT::decode($token, $config['key']);
var_dump($payload);