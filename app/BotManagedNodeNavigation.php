<?php

/** Node route screens reuse exit controls without losing their parent menu. */
trait BotManagedNodeNavigation
{
    public array $managedNodeNavigation = [];

    public function managedNodeNavigationStart(): void
    {
        $this->managedNodeNavigation = [];
        $callback = (string) ($this->input['callback'] ?? '');
        if (preg_match('~^/nt([a-f0-9]{8}) (.+)$~D', $callback, $m)) {
            if (!isset($this->managedNodes()[$m[1]]) || !self::managedNodeDatCallback('/'.$m[2])) { $this->input['callback']='/nodes'; return; }
            $this->managedNodeNavigation = ['id'=>$m[1], 'area'=>'t'];
            $this->input['callback'] = '/'.$m[2];
            return;
        }
        if (preg_match('~^/n([rud])([A-Za-z]*) ([a-f0-9]{8})(.*)$~D', $callback, $m)) {
            if (!isset($this->managedNodes()[$m[3]])) {
                $this->input['callback'] = '/nodes';
                return;
            }
            $this->managedNodeNavigation = ['id' => $m[3], 'area' => $m[1]];
            $this->input['callback'] = '/exit' . $m[2] . ' ' . $m[3] . $m[4];
        }
    }

    /**
     * A node job redraws its origin message when it finishes. Once the admin
     * presses another button in that message, the screen belongs to them: the
     * job then reports by a separate notice instead of replacing their menu.
     */
    public function managedNodeTrackScreen(): void
    {
        $callback = (string) ($this->input['callback'] ?? '');
        if ($callback === '' || empty($this->input['message_id']) || empty($this->input['chat'])) return;
        foreach ($this->managedNodes() as $id => $node) {
            $origin = $node['job']['origin'] ?? null;
            // The node screen itself and its refresh keep the origin owned by the job.
            if (!is_array($origin) || !empty($origin['moved']) || in_array($callback, ["/node $id", "/nodeRefresh $id"], true)
                || (string) ($origin['chat'] ?? '') !== (string) $this->input['chat']
                || (int) ($origin['message_id'] ?? 0) !== (int) $this->input['message_id']) continue;
            $this->managedNodeWrite((string) $id, static function (&$node) {
                if (!empty($node['job']['origin'])) $node['job']['origin']['moved'] = true;
            });
        }
    }

    private static function managedNodeDatCallback(string $callback): bool
    {
        return (bool) preg_match('~^/(?:xtlsdat|dat(?:schedule(?:set|custom|hour)?|files|refresh|cats|catsearch)|(?:change|delete)datlist)(?: |$)|^/(?:include|dedupeList|deleteAll|exportList|importList) datlist(?: |$)~D', $callback);
    }

    public function managedNodeNavigationButtons($buttons)
    {
        if (!$this->managedNodeNavigation || !is_array($buttons)) return $buttons;
        ['id' => $id, 'area' => $area] = $this->managedNodeNavigation;
        foreach ($buttons as &$row) foreach ($row as &$button) {
            $callback = $button['callback_data'] ?? '';
            if ($callback === '/xtlsdat' || ($area === 't' && self::managedNodeDatCallback($callback))) $callback = "/nt$id " . substr($callback, 1);
            elseif ($area === 't' && $callback === '/routes') $callback = "/nrDat $id";
            elseif ($area === 't' && str_starts_with($callback, '/menuhelp ')) $callback = "/menuhelp managednodes 0 t_$id";
            elseif ($callback === '/exits' || ($area !== 'r' && $callback === "/exit $id")) $callback = "/node $id";
            elseif (preg_match('~^/exit([A-Za-z]*) ' . preg_quote($id, '~') . '( |$)~D', $callback)) {
                $callback = '/n' . $area . substr($callback, 5);
            } elseif (str_starts_with($callback, '/menuhelp exitnodes ')) {
                $callback = "/menuhelp managednodes 0 {$area}_$id";
            }
            if (isset($button['callback_data'])) $button['callback_data'] = $callback;
        }
        return $buttons;
    }
}
