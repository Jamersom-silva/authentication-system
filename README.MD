# Authentication System

Projeto básico de sistema de autenticação em Django, com funcionalidades para registro, login, logout, ativação por email, redefinição de senha, autenticação via JWT e 2FA.

---

## Funcionalidades

- Registro de usuário com ativação via email
- Login e logout tradicionais (formulários Django)
- Autenticação via API REST com JWT
- Redefinição de senha por email
- Autenticação de dois fatores (2FA) via código enviado por email
- Suporte para OAuth social (Google, GitHub, etc)
- Proteção contra múltiplas tentativas de login com cache
- Dashboard protegido para usuários autenticados

---

## Tecnologias

- Python 3.11
- Django 5.2
- Django REST Framework
- Simple JWT
- SQLite (banco de dados padrão)
- Email backend para envio de emails (configurar SMTP)

---

## Como usar

1. Clone o repositório:

```bash
git clone https://github.com/Jamersom-silva/authentication-system.git
cd authentication-system
