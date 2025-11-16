"""
main_cli.py
-------------------
Interface de linha de comando (CLI) para demonstrar o funcionamento do
sistema WorkShield, incluindo:

- Cadastro de usuários (signup)
- Login e geração de token
- Envio de mensagens para análise de segurança
- Detecção automática de incidentes
- Consulta de incidentes registrados
- Verificação de identidade (whoami)
- Logout

Este arquivo serve apenas como interface de demonstração.
Toda a lógica de segurança, autenticação e detecção de incidentes está
implementada em workshield.py.
"""

from workshield import WorkShieldSystem

def main():
    """
    Executa o loop principal da CLI do WorkShield.

    A função inicializa o sistema, exibe os comandos disponíveis e
    processa interativamente entradas do usuário.

    Comandos suportados:
        - signup <user> <pass>
            Registra um novo usuário no sistema.

        - login <user> <pass>
            Autentica um usuário e retorna um token de sessão.

        - send <token> <message>
            Envia uma mensagem para análise de segurança e potencial
            geração de incidentes.

        - list <token>
            Lista todos os incidentes registrados (necessita token válido).

        - whoami <token>
            Retorna o nome do usuário associado ao token.

        - logout <token>
            Encerra a sessão correspondente ao token informado.

        - exit
            Encerra o programa.

    O método opera em loop até que o usuário digite 'exit'.
    """
    ws = WorkShieldSystem()

    print("\n=== WorkShield CLI Demo ===")
    print("Comandos disponíveis:")
    print("  signup <user> <pass>")
    print("  login <user> <pass>")
    print("  send <token> <message>")
    print("  list <token>")
    print("  whoami <token>")
    print("  logout <token>")
    print("  exit")
    print("===========================\n")

    while True:
        try:
            cmd = input(">> ").strip()
        except EOFError:
            break

        if not cmd:
            continue

        parts = cmd.split(" ", 2)
        op = parts[0]

        # SIGNUP
        if op == "signup" and len(parts) >= 3:
            u = parts[1]
            p = parts[2]
            ok = ws.signup(u, p)
            print("Usuário criado com sucesso!" if ok else "Erro: usuário já existe.")

        # LOGIN
        elif op == "login" and len(parts) >= 3:
            u = parts[1]
            p = parts[2]
            tok = ws.login(u, p)
            if tok:
                print("\n=== LOGIN EFETUADO ===")
                print("TOKEN:", tok)
                print("Guarde este token — ele autentica suas ações no sistema.")
                print("Com este token, você pode usar:")
                print("  whoami <token>")
                print("  send <token> <mensagem>")
                print("  list <token>")
                print("  logout <token>")
                print("=======================\n")
            else:
                print("Login failed.")

        # SEND MESSAGE
        elif op == "send" and len(parts) >= 3:
            tok = parts[1]
            msg = parts[2]

            user = ws.get_user_by_token(tok)
            if not user:
                print("Token inválido.")
                continue

            result = ws.ingest_message("cli", user.username, msg)
            if result:
                inc, user_msg = result
                print("\n=== INCIDENTE GERADO ===")
                print("Incident created:", inc)
                print("\nMensagem recebida pelo usuário:")
                print(user_msg)
                print("==========================\n")
            else:
                print("Nenhum problema detectado.")

        # LIST INCIDENTS
        elif op == "list" and len(parts) >= 2:
            tok = parts[1]
            try:
                incs = ws.list_incidents(tok)
                if not incs:
                    print("Nenhum incidente registrado.")
                else:
                    print("\n=== INCIDENTES ===")
                    for i in incs:
                        print(i)
                    print("===================\n")
            except Exception as e:
                print("Erro:", e)

        # WHOAMI
        elif op == "whoami" and len(parts) >= 2:
            tok = parts[1]
            user = ws.get_user_by_token(tok)
            if user:
                print(f"Você é: {user.username}")
            else:
                print("Token inválido.")

        # LOGOUT
        elif op == "logout" and len(parts) >= 2:
            tok = parts[1]
            ok = ws.logout(tok)
            print("Logout realizado com sucesso." if ok else "Token inválido.")

        # EXIT
        elif op == "exit":
            break

        else:
            print("Comando desconhecido ou incorreto.")


if __name__ == '__main__':
    main()
