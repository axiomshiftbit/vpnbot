<?php

trait BotServiceDiagnostics
{
    public static function serviceErrorText(string $code): string
    {
        return match ($code) {
            '' => 'нет',
            'tls_expired' => 'сертификат TLS истёк; обновите SSL',
            'tls_not_yet_valid' => 'сертификат TLS ещё не действует; проверьте время сервера',
            'tls_name_mismatch' => 'сертификат не соответствует SNI',
            'tls_key_mismatch' => 'сертификат TLS и закрытый ключ не соответствуют друг другу',
            'tls_invalid' => 'сертификат TLS не прошёл проверку',
            'tls_unavailable' => 'не удалось прочитать сертификат или ключ TLS',
            'port_in_use' => 'порт уже занят; выберите свободный порт',
            'port_unavailable' => 'порт или адрес недоступен для привязки',
            'core_unavailable' => 'исполняемый файл ядра отсутствует или недоступен',
            'configuration_rejected' => 'ядро отклонило конфигурацию; проверьте параметры',
            'stats_unavailable', 'quota_stats_unavailable' => 'недоступен учёт трафика',
            'start_failed' => 'ядро не подтвердило готовность после запуска',
            default => 'состояние или конфигурация недоступны; проверьте сервис',
        };
    }

    public function serviceDiagnosticLines(string $scope): array
    {
        $store = $this->accessStore($scope); $state = $store->read(); $status = $store->status();
        $name = $scope === 'hy' ? 'Hysteria' : ManagedProtocol::NAMES[$scope];
        $lines = [$name . ' → Диагностика'];
        $fresh = ($status['time'] ?? 0) >= time() - 15;
        $lines[] = 'Состояние: ' . (!$fresh ? 'нет свежего ответа контроллера' : (!empty($status['running']) ? 'работает' : 'остановлен'));
        $lines[] = 'Применение настроек: ' . (($status['revision'] ?? null) === $state['revision'] ? 'завершено' : 'ожидается');
        $lines[] = 'Ошибка: ' . self::serviceErrorText((string) ($status['error'] ?? ''));
        foreach (['last_validation' => 'Последняя успешная проверка', 'last_success' => 'Последнее успешное применение'] as $field => $label) {
            $lines[] = $label . ' (UTC): ' . (!empty($status[$field]) ? gmdate('Y-m-d H:i:s', $status[$field]) : 'ещё нет данных');
        }
        $cert = null;
        if ($scope === 'hy') {
            $config = @yaml_parse_file($this->hysteriaConf);
            if (is_array($config) && is_string($config['tls']['cert'] ?? null)) $cert = $config['tls']['cert'];
        } elseif (in_array($scope, ['anytls', 'tuic', 'masque'], true)) $cert = $state['settings']['certificate'];
        elseif ($scope === 'shadowtls' && !empty($state['settings']['self_hosted'])) $cert = '/certs/cert_public';
        if ($cert !== null) {
            try {
                $path = $this->managedCertificatePath($cert);
                $pem = @file_get_contents($path, false, null, 0, 1048576);
                $info = $pem ? @openssl_x509_parse($pem) : false;
            } catch (RuntimeException | InvalidArgumentException $e) { $info = false; }
            if (!$info || empty($info['validTo_time_t'])) $lines[] = 'TLS: сертификат не найден или повреждён';
            else {
                $end = $info['validTo_time_t']; $start = $info['validFrom_time_t'] ?? 0;
                $phase = $end <= time() ? 'истёк' : ($start > time() ? 'ещё не действует' : 'действует');
                $lines[] = 'TLS: ' . $phase . '; до ' . gmdate('Y-m-d H:i', $end) . ' UTC';
            }
        } elseif ($scope === 'mieru') $lines[] = 'TLS: не используется протоколом Mieru';
        elseif ($scope === 'shadowtls') $lines[] = 'TLS сайта прикрытия проверяется клиентом; локального сертификата нет';
        if ($scope !== 'hy') {
            $file = dirname($this->protocolModulesFile) . '/protocol-services.status.json';
            $modules = is_file($file) ? ManagedProtocol::readJson($file) : [];
            if (isset($modules['errors'][$scope])) $lines[] = 'Публикация порта: ' . self::serviceErrorText((string) $modules['errors'][$scope]);
            else $lines[] = 'Публикация порта: ' . ($this->protocolPortApplied($scope, $state) ? 'применена' : 'ожидается');
        }
        return $lines;
    }

    public function serviceDiagnostics(string $scope): void
    {
        if (!$this->admin) return;
        $back = $scope === 'hy' ? '/menu hy' : "/protocol $scope";
        try {
            $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", array_map([self::class, 'esc'], $this->serviceDiagnosticLines($scope))), [
                [['text' => 'Обновить', 'callback_data' => "/diag $scope"]],
                [['text' => $this->i18n('back'), 'callback_data' => $back]],
            ]);
        } catch (RuntimeException | InvalidArgumentException $e) { $this->protocolError($e->getMessage(), $back); }
    }
}
