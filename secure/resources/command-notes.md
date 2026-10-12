# OS Command Injection — short notes

- Sink: the OS shell.
- Root cause: user input concatenated into a shell command string.
- Fix: avoid the shell; pass an argument vector. Validate with an allowlist.