
WORKSHIELD - GLOBAL SOLUTION 
============================================================

### Sistema de Detecção Automática de Incidentes de Segurança

------------------------------------------------------------
1. VISÃO GERAL DO SISTEMA
------------------------------------------------------------

O WorkShield é um sistema desenvolvido para monitorar, analisar e
identificar automaticamente possíveis incidentes de segurança em textos
enviados por usuários, garantindo proteção, rastreabilidade e registro
de evidências.

#### Principais funcionalidades:
- Cadastro e autenticação segura de usuários
- Análise automática de mensagens
- Detecção de informações sensíveis (PII)
- Identificação de domínios maliciosos
- Geração automática de incidentes
- Controle de sessões com token
- Registro detalhado de logs de operação
- Armazenamento eficiente utilizando Árvore AVL (O(log N))

------------------------------------------------------------
2. ESTRUTURA DO PROJETO
------------------------------------------------------------

main_cli.py        → Interface em modo texto (CLI)

workshield.py      → Lógica principal do sistema

models.py          → Classes User e Incident

avl.py             → Implementação completa da árvore AVL

workshield.log     → Arquivo contendo todos os logs

README.txt         → Documento explicativo do projeto

------------------------------------------------------------
3. REQUISITOS TÉCNICOS ATENDIDOS
------------------------------------------------------------

LINGUAGEM
- Projeto implementado integralmente em Python
- Uso exclusivo da biblioteca padrão

ORIENTAÇÃO A OBJETOS
- Classes: User, Incident, AVLNode, AVLTree, WorkShieldSystem
- Encapsulamento e modularização aplicados

ESTRUTURA DE DADOS
- Árvore AVL implementada manualmente
- Operações garantidas em O(log N)

SEGURANÇA
- Hash seguro de senha com PBKDF2-HMAC-SHA256
- Salt aleatório por usuário
- Tokens de sessão gerados com secrets.token_hex
- Controle de sessão e prevenção de acesso indevido
- Detecção automática de dados sensíveis e URLs maliciosas

INTERFACE
- CLI simples, amigável e compatível com qualquer sistema operacional

LOGS
- Todas as operações relevantes são registradas
- Registros armazenados no arquivo workshield.log

------------------------------------------------------------
4. COMO EXECUTAR O SISTEMA
------------------------------------------------------------

1. Certifique-se de que o Python 3.x está instalado.
2. No terminal, execute:

       python3 main_cli.py

3. Use os comandos disponíveis na interface CLI.

------------------------------------------------------------
5. COMANDOS DISPONÍVEIS (CLI)
------------------------------------------------------------

signup < usuario > < senha >

login < usuario > < senha >

send < token > < mensagem >

list < token >

whoami < token >

logout < token >

exit

------------------------------------------------------------
6. EXEMPLO DE EXECUÇÃO
------------------------------------------------------------

> signup ana 123456
Usuário criado com sucesso.

> login ana 123456
Token gerado: a93f1d0c8b...

> send a93f1d0c8b "meu cpf é 123.456.789-10"
INCIDENTE GERADO: Tipo = CPF | Severidade = Alta

> list a93f1d0c8b
INC00001 | CPF detectado | Severidade Alta

------------------------------------------------------------
7. DOCUMENTAÇÃO (PYDOC)
------------------------------------------------------------

Todas as funções, classes e métodos possuem documentação em formato
Pydoc. Cada arquivo apresenta docstrings explicando:

- Objetivo da classe ou função
- Parâmetros recebidos
- Valor de retorno
- Comportamento geral

A documentação foi implementada nos arquivos:
- workshield.py
- avl.py
- main_cli.py

------------------------------------------------------------
8. TESTES REALIZADOS
------------------------------------------------------------

- Criação de usuários
- Login com senha incorreta
- Envio de mensagens com PII
- Envio de mensagens sem incidentes
- Detecção de domínios maliciosos
- Testes de balanceamento da AVL
- Teste de tokens inválidos
- Verificação da geração e gravação de logs

------------------------------------------------------------
9. CONCLUSÃO
------------------------------------------------------------

O WorkShield atende 100% desses requisitos:
- Estrutura de dados eficiente (AVL)
- Segurança avançada com PBKDF2 e tokens
- Interface CLI funcional
- Identificação automática de incidentes
- Arquitetura modular e orientada a objetos
- Logs detalhados
- Desempenho garantido em O(log N)


------------------------------------------------------------
10. CONTATO
------------------------------------------------------------

Autora: Ane Katerinne Ribeiro
FIAP — 2025
