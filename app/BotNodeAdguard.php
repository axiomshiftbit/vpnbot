<?php

/** The node's DNS data plane and its short-lived administration session are independent. */
trait BotNodeAdguard
{
    private function nodeAdguardEnabled(array $node): bool
    {
        return !empty($node['connected']) && !empty($node['status']['adguard_filter'])
            && !empty($node['status']['options']['adguard']['enabled']);
    }

    private function nodeAdguardSessionValid(array $node): bool
    {
        $grant = $node['adguard_panel'] ?? [];
        return $this->nodeAdguardEnabled($node) && ($grant['until'] ?? 0) > time()
            && !empty($grant['generation']) && $grant['generation'] === ($node['status']['generation'] ?? '');
    }

    public function nodeAdguardMenu(string $id, string $notice = ''): void
    {
        $node = $this->managedNodes()[$id] ?? [];
        if (empty($node['status']['adguard_filter'])) { $this->managedNodeMenu($id); return; }
        $options = $node['status']['options']['adguard'] ?? [];
        $grant = $this->nodeAdguardSessionValid($node);
        $text = [$this->t('Нода → AdGuard Home', 'Node → AdGuard Home'),
            $this->t('DNS-фильтр доступен через VPN. Сайт панели открывает основной бот по одноразовой ссылке.', 'The DNS filter is accessible through the VPN. The main bot opens the panel using a single-use link.'),
            $grant ? $this->t('Доступ к панели до ', 'Panel access until ') . date('H:i:s', $node['adguard_panel']['until']) : $this->t('Доступ к панели закрыт', 'Panel access closed')];
        $data = [[['text' => $this->t('Настройки фильтра', 'Filter settings'), 'callback_data' => "/nodeSettings $id network"]]];
        if ($this->nodeAdguardEnabled($node)) {
            $text[] = $this->t('Доступ к DNS через основной бот', 'DNS access via the main bot') . ' · ' . $this->i18n(!empty($options['controller']) ? 'on' : 'off');
            $peers = array_filter($this->managedNodePeers($id), static fn($p) => $p['enabled'] && in_array($p['id'], $options['peers'] ?? [], true));
            $text[] = $this->t('Разрешено прямых подключений', 'Allowed direct connections') . ' · ' . count($peers);
            $data[] = [['text' => $this->t('Заполнить разрешённых клиентов', 'Fill allowed clients'), 'callback_data' => "/nodeAdClients $id fill"],
                ['text' => $this->t('Запретить всем', 'Deny all clients'), 'callback_data' => "/nodeAdClients $id deny"]];
            $data[] = [['text' => $this->t('Ссылка на панель · 15 минут', 'Panel link · 15 minutes'), 'callback_data' => "/nodeAdOpen $id"]];
            if ($grant) $data[] = [['text' => $this->t('Закрыть доступ к панели', 'Close panel access'), 'callback_data' => "/nodeAdClose $id"]];
        }
        if ($notice !== '') $text[] = self::esc($notice);
        $data[] = [['text' => $this->i18n('back'), 'callback_data' => "/node $id"]];
        $this->update($this->input['chat'], $this->input['message_id'], implode("\n\n", $text), $data);
    }

    public function nodeAdguardClients(string $id, bool $allow): void
    {
        $draft = false;
        try {
            $this->managedNodeLocked($id, function () use ($id, $allow, &$draft) {
                $node = $this->managedNodes()[$id] ?? [];
                if (!$this->nodeAdguardEnabled($node) || !empty($node['job'])) throw new RuntimeException('DNS filter unavailable');
                $generation = (string) $node['status']['generation'];
                $options = $node['draft'] ?? $node['status']['options'];
                $peers = $this->managedNodePeers($id, $node['status']);
                $options['adguard']['controller'] = $allow;
                $options['adguard']['peers'] = $allow ? array_values(array_column(array_filter($peers, static fn($p) => $p['enabled']), 'id')) : [];
                if (isset($node['draft'])) {
                    if (($node['draft_generation'] ?? '') !== $generation) throw new RuntimeException('Stale settings draft');
                    $this->managedNodeWrite($id, static function (&$saved) use ($options) { $saved['draft'] = $options; });
                    $draft = true;
                } else {
                    $this->managedNodeSubmitLocked($id, 'configure', $options, $generation);
                }
            });
            if ($draft) $this->managedNodeSettingsMenu($id, 'network', $this->t('Список клиентов добавлен в черновик. Нажмите «Применить».', 'The client list is in the draft. Select Apply.'));
            else $this->managedNodeMenu($id);
        } catch (Throwable $e) { $this->nodeAdguardMenu($id, $this->t('Изменение не принято. Обновите карточку ноды.', 'Change rejected. Refresh the node card.')); }
    }

    public function nodeAdguardOpen(string $id): void
    {
        if ((int) ($this->input['from'] ?? 0) <= 0) { $this->nodeAdguardMenu($id); return; }
        $ticket = bin2hex(random_bytes(32));
        $this->managedNodeWrite($id, function (&$node) use ($ticket) {
            if (!$this->nodeAdguardEnabled($node) || empty($node['status']['generation'])) throw new RuntimeException('DNS filter unavailable');
            $node['adguard_panel'] = ['until' => time() + self::ADGUARD_LINK_TTL, 'generation' => $node['status']['generation'],
                'ticket' => hash('sha256', $ticket)];
        });
        $url = 'https://' . $this->getDomain() . '/webapp' . $this->getHashBot() . '/nad/' . $id . '/_open#' . $ticket;
        // Send the invitation privately, even when the initiating chat is a group.
        $this->send($this->input['from'], $this->t('Одноразовая ссылка. Доступ закрывается через 15 минут после выдачи.', 'Single-use link. Access closes 15 minutes after issue.') . "\n<code>" . self::esc($url) . '</code>');
        $this->nodeAdguardMenu($id);
    }

    public function nodeAdguardClose(string $id): void
    {
        $this->managedNodeWrite($id, static function (&$node) { unset($node['adguard_panel']); });
        $this->nodeAdguardMenu($id);
    }

    public function nodeAdguardExchange(string $id, string $ticket): ?array
    {
        if (!preg_match('~^[a-f0-9]{64}$~D', $ticket)) return null;
        $digest = hash('sha256', $ticket);
        $matches = fn($node) => is_array($node) && $this->nodeAdguardSessionValid($node)
            && isset($node['adguard_panel']['ticket']) && hash_equals($node['adguard_panel']['ticket'], $digest);
        if (!$matches($this->managedNodes()[$id] ?? null)) return null;
        $issued = null;
        $this->managedNodeWrite($id, function (&$node) use ($matches, &$issued) {
            if (!$matches($node)) return false;
            $token = bin2hex(random_bytes(32));
            unset($node['adguard_panel']['ticket']);
            $node['adguard_panel']['session'] = hash('sha256', $token);
            $issued = [$token, $node['adguard_panel']['until']];
        });
        return $issued;
    }

    public function nodeAdguardAuthorized(string $id, string $cookie): bool
    {
        $node = $this->managedNodes()[$id] ?? [];
        return $this->nodeAdguardSessionValid($node) && preg_match('~^[a-f0-9]{64}$~D', $cookie)
            && isset($node['adguard_panel']['session']) && hash_equals($node['adguard_panel']['session'], hash('sha256', $cookie));
    }

    public function nodeAdguardWeb(string $id, string $path, string $prefix): void
    {
        header('Cache-Control: private, no-store');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $sameOrigin = ($_SERVER['HTTP_ORIGIN'] ?? '') === 'https://' . $this->getDomain();
        if ($path === '_open' && $method === 'GET' && $this->nodeAdguardSessionValid($this->managedNodes()[$id] ?? [])) {
            $nonce = base64_encode(random_bytes(20));
            header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
            header('Content-Type: text/html; charset=utf-8');
            $action = $this->t('Открыть AdGuard Home', 'Open AdGuard Home');
            $error = $this->t('Ссылка недействительна или истекла', 'The link is invalid or has expired');
            echo '<!doctype html><html lang="' . ($this->language === 'en' ? 'en' : 'ru')
                . '"><meta charset="utf-8"><title>AdGuard Home</title><button>' . self::esc($action) . '</button><p hidden>'
                . self::esc($error) . '</p><script nonce="' . $nonce . '">'
                . 'const token=location.hash.slice(1);history.replaceState(null,"",location.pathname);document.querySelector("button").onclick=async function(){this.disabled=true;try{const r=await fetch("_exchange",{method:"POST",body:token});if(r.ok){location.replace("./");return}}catch(e){}document.querySelector("p").hidden=false};</script>';
            return;
        }
        if ($path === '_exchange' && $method === 'POST' && $sameOrigin) {
            $issued = $this->nodeAdguardExchange($id, (string) file_get_contents('php://input', false, null, 0, 65));
            if ($issued && setcookie('nad', $issued[0], ['expires' => $issued[1], 'path' => $prefix, 'secure' => true, 'httponly' => true, 'samesite' => 'Strict'])) {
                http_response_code(204); return;
            }
        }
        $cookie = is_string($_COOKIE['nad'] ?? null) ? $_COOKIE['nad'] : '';
        if (!$this->nodeAdguardAuthorized($id, $cookie)) { http_response_code(404); return; }
        if (!in_array($method, ['GET','HEAD'], true) && !$sameOrigin) { http_response_code(403); return; }
        if ($path === 'control/logout' && $method === 'GET') {
            if (($_SERVER['HTTP_SEC_FETCH_SITE'] ?? 'same-origin') !== 'same-origin'
                || (isset($_SERVER['HTTP_ORIGIN']) && !$sameOrigin)) { http_response_code(403); return; }
            $this->managedNodeWrite($id, static function (&$node) use ($cookie) {
                if (!isset($node['adguard_panel']['session']) || !hash_equals($node['adguard_panel']['session'], hash('sha256', $cookie))) return false;
                unset($node['adguard_panel']);
            });
            setcookie('nad', '', ['expires' => 1, 'path' => $prefix, 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
            header('Content-Type: text/plain; charset=utf-8');
            echo $this->t('Доступ к панели закрыт', 'Panel access closed');
            return;
        }
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'");
        if (!str_starts_with($path, 'control/')) {
            if (!in_array($method, ['GET','HEAD'], true)) { http_response_code(405); return; }
            $path = $path === '' ? 'index.html' : $path;
            $types = ['html'=>'text/html','js'=>'application/javascript','css'=>'text/css','svg'=>'image/svg+xml','json'=>'application/json',
                'png'=>'image/png','ico'=>'image/x-icon','woff'=>'font/woff','woff2'=>'font/woff2','ttf'=>'font/ttf','webp'=>'image/webp'];
            $type = $types[pathinfo($path, PATHINFO_EXTENSION)] ?? null;
            $root = '/vpnbot-panel-assets';
            $file = realpath($root . '/' . $path);
            if (!$type || !$file || !str_starts_with($file, $root.'/') || !is_file($file)) { http_response_code(404); return; }
            header('Content-Type: '.$type);
            if ($method === 'GET') readfile($file);
            return;
        }
        $body = file_get_contents('php://input', false, null, 0, 1048577);
        if ($body === false || strlen($body) > 1048576) { http_response_code(413); return; }
        $query = $_SERVER['QUERY_STRING'] ?? '';
        $reply = $this->managedNodeTransport($id, 'adguard_panel', ['method' => $method,
            'path' => '/'.$path.($query === '' ? '' : '?'.$query), 'body' => base64_encode($body),
            'type' => strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]))]);
        // Only data comes from the remote node. Executable UI assets are served
        // by the controller's immutable AdGuard image at the same subpath.
        $bytes = base64_decode($reply['body'] ?? '', true);
        if ($bytes === false || !$this->nodeAdguardAuthorized($id, $cookie)) { http_response_code(403); return; }
        $status = $reply['status'] ?? 502;
        http_response_code(is_int($status) && $status >= 200 && $status <= 599 ? $status : 502);
        header('Content-Type: '.(($reply['type'] ?? '') === 'application/json' ? 'application/json' : 'text/plain').'; charset=utf-8');
        if ($method !== 'HEAD') echo $bytes;
    }
}
