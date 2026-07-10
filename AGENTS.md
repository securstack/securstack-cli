# AGENTS.md

Instrucoes para agentes trabalhando no `securstack-cli`.

## Papel do repositorio

`securstack-cli` e o cliente local do SecurStack para scans de seguranca em repositorios locais, automacoes de CI e integracoes com plugins de IDE.

## Regras de escopo

- O motor principal de analise deve permanecer na API do SecurStack.
- O CLI deve preparar o workspace local, aplicar ignores, autenticar com API key e chamar a API existente.
- Contratos compartilhados devem ser definidos em `securstack-core` quando forem usados por mais de um repositorio.
- Nao copie logica de runtime de `securstack-api`, `securstack-workers` ou dos plugins de IDE.
- Nao versione API keys, tokens, dumps de repositorios ou payloads sensiveis.

## Padroes esperados

- Comandos devem ser idempotentes sempre que possivel.
- Saidas para integracoes devem suportar JSON e, quando aplicavel, SARIF.
- O CLI deve respeitar `.gitignore` e `.securstackignore`.
- Erros devem ser acionaveis e apropriados para uso interativo e CI.
