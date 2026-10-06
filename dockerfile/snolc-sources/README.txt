Закреплённые исходники snolc 0.0.4

snolc-source.tar.gz: owenewans/snolc, commit d71069837c12816b625c09ed0cd6ec1e3b4a7354.
SHA256: 945144323ac0c1c71cf2a3ea6a5ef082b101baa63ca0a679f357df2130991e0d.
modules-source.tar.gz: owenewans/snolc-modules, commit bdc701687ac4d69961e9d325db6be07d748a6e0a.
SHA256: f07ae9949c89875365bf65d4eb01d737fc8307f323ac24e4d44af4579c1e3c7e.

Это неизменённые архивы codeload.github.com, ранее закреплённые Dockerfile.
Их копии включены в исходники продукта, поскольку прежние GitHub URL
перестали отдавать исходники и релизы. LICENSE сохранён внутри архивов.
Модули собираются с SDK/ABI из того же закреплённого дерева, что и ядро;
snolc-modules.patch заменяет недоступную Git-зависимость локальным путём.
Версии остальных Cargo-зависимостей сохраняются, сборка использует --locked.

app/snolc/archives содержит исходные релизы Linux x86_64 с неизменными
SHA256 из app/snolc/releases.json, LICENSE и THIRD_PARTY_NOTICES.txt.
Dockerfile накладывает исправления VPNBot. Полный клиентский комплект
доставляется ботом и устанавливается без загрузок из внешнего репозитория.
При обновлении менять архивы, SHA256 и патчи согласованно; обязательны
тесты Cargo и полный VPNBotTest, включая экспорт и чистую установку клиента.
