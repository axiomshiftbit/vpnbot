<?php

trait BotChatNavigation
{
    protected bool $chatNavigationActive = false;

    // Удаляем только известные временные ответы этого администратора в этом
    // чате. Уведомления cron, документы/бэкапы и чужие сообщения сюда не входят.
    public function chatNavigationStart(): void
    {
        $this->chatNavigationActive = $this->admin && !empty($this->input['from']) && !empty($this->input['chat']);
        if (!$this->chatNavigationActive) return;
        $chat = (string) $this->input['chat'];
        $current = (int) ($this->input['message_id'] ?? 0);
        $outputs = [];
        $this->sessionApply(function () use ($chat, &$outputs) {
            $outputs = $_SESSION['menu_output'][$chat] ?? [];
            unset($_SESSION['menu_output'][$chat]);
        });
        foreach ($outputs as $id) {
            if ((int) $id !== $current) $this->delete($chat, $id);
        }
    }

    protected function chatOwnsOutput($chat): bool
    {
        return $this->chatNavigationActive && (string) $chat === (string) ($this->input['chat'] ?? '');
    }

    protected function rememberChatOutput($chat, $result)
    {
        if (!$this->chatOwnsOutput($chat) || empty($result['ok']) || empty($result['result']['message_id'])) return $result;
        $id = (int) $result['result']['message_id'];
        $this->sessionApply(function () use ($chat, $id) {
            $ids = $_SESSION['menu_output'][(string) $chat] ?? [];
            $ids[] = $id;
            $_SESSION['menu_output'][(string) $chat] = array_values(array_unique($ids));
        });
        return $result;
    }

    protected function rememberChatMenu($chat, int $id): void
    {
        if (!$this->chatOwnsOutput($chat) || $id <= 0) return;
        $previous = 0;
        $this->sessionApply(function () use ($chat, $id, &$previous) {
            $previous = (int) ($_SESSION['menu_anchor'][(string) $chat] ?? 0);
            $_SESSION['menu_anchor'][(string) $chat] = $id;
        });
        if ($previous > 0 && $previous !== $id) $this->delete($chat, $previous);
    }

    protected function chatMenuAnchor($chat): int
    {
        if (!$this->chatOwnsOutput($chat)) return 0;
        $id = 0;
        $this->sessionApply(function () use ($chat, &$id) {
            $id = (int) ($_SESSION['menu_anchor'][(string) $chat] ?? 0);
        });
        return $id;
    }
}
