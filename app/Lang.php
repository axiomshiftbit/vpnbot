<?php

// Язык интерфейса для классов без доступа к Bot: их сообщения об ошибках
// проверок бот показывает пользователю как есть. Bot выставляет язык вместе со
// своим $language; по умолчанию — русский, как было до перевода.
final class Lang
{
    public static bool $en = false;

    public static function t(string $ru, string $en): string
    {
        return self::$en ? $en : $ru;
    }
}
