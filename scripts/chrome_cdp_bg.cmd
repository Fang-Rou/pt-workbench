@echo off
rem CDP browser for butian login state (port 9223).
rem Uses ASCII junction C:\chrome-cdp-profile -> workspace chrome-profile.
rem NEVER put non-ASCII into this file or into the chrome command line:
rem job.py -> WMI -> cmd.exe reads .cmd as CP936, so a UTF-8 Chinese path gets mangled
rem and Chrome silently creates a NEW profile at the mojibake path (hit on 2026-09-18).
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9223 --remote-allow-origins=* --user-data-dir=C:\chrome-cdp-profile --no-first-run --no-default-browser-check about:blank
