# XSS — short notes

- Sink: the HTML parser in the victim's browser.
- Root cause: untrusted data rendered as markup.
- Fix: output encoding (Jinja2 autoescape) + CSP + HttpOnly cookies.