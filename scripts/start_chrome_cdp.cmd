@echo off
rem 工作区 CDP 浏览器（9223）：profile 走 C:\chrome-cdp-profile junction，避开中文路径编码坑
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9223 --remote-allow-origins=* --user-data-dir=C:\chrome-cdp-profile --no-first-run --no-default-browser-check about:blank