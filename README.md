# securstack-cli

Cliente local do SecurStack para executar scans de seguranca em repositorios locais usando a API existente do SecurStack.

## Responsabilidades

- Descobrir e preparar o workspace local.
- Respeitar `.gitignore` e `.securstackignore`.
- Autenticar com API key do usuario.
- Criptografar localmente e enviar os arquivos permitidos para a API do SecurStack.
- Retornar findings em formatos reutilizaveis por IDEs e CI.

O CLI recebe resposta sincrona da API, mas os motores de analise rodam no SaaS do SecurStack, nos workers internos.

## Uso inicial

```bash
securstack login --api-key ssk_live_...
securstack scan --path . --format json
securstack scan --path . --format sarif
securstack scan --path . --format sarif --output securstack.sarif
securstack doctor
securstack logout
```

Tambem e possivel usar variaveis de ambiente:

```bash
SECURSTACK_API_KEY=ssk_live_... SECURSTACK_API_URL=https://api.securstack.io/api securstack scan
```

## Privacidade e envio de codigo

O CLI criptografa localmente os arquivos elegiveis antes de envia-los para a API do SecurStack. O fluxo usa uma sessao efemera de scan com `X25519 + HKDF-SHA256` para derivacao de chave e `AES-256-GCM` por arquivo. A API recebe apenas ciphertext e metadados; a descriptografia acontece no worker interno que executa os motores de scan.

Antes do envio, ele:

- respeita `.gitignore` e `.securstackignore`;
- ignora diretorios comuns como `.git`, `node_modules`, `dist`, `build`, `coverage`, `.next`, `.turbo`, `.cache` e `.idea`;
- ignora arquivos binarios;
- aplica limites locais de tamanho por arquivo, total de payload e numero de arquivos.

Use `.securstackignore` para excluir arquivos sensiveis que nao devem sair da maquina.

## `.securstackignore`

O formato inicial segue um subconjunto simples de `.gitignore`:

```gitignore
.env
.env.*
secrets/
*.pem
fixtures/private-data.json
```

Negacoes com `!` ainda nao sao aplicadas nesta versao.

## Release

O pacote expoe o binario `securstack` via `package.json#bin`. A distribuicao inicial recomendada e npm privado/publico:

```bash
npm pack
npm publish
```

## Consumidores previstos

- `securstack-plugin-vscode`
- `securstack-plugin-jetbrains`
- Pipelines de CI/CD
