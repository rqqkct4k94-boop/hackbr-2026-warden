# FAROL-26 · Abrir um cofre de evidências

Abra `farol-26.html` em uma janela privada de um navegador moderno. Clique em **Abrir o cofre**. Para a apresentação automática, marque **Demonstrar caso automaticamente** antes de começar. Durante o percurso, use **Pausar demonstração**, **Demonstrar caso** para retomar e **Reiniciar** para voltar ao início. Cada resultado fica visível por pelo menos 7,5 segundos no modo automático.

## Compilar e repetir

Na raiz deste checkout, com Node 22.12+ e npm, execute os comandos abaixo. O download das dependências públicas ocorre durante o build. O HTML pronto inclui o código de verificação e as evidências e funciona sem rede.

```sh
npm ci --prefix demo/judge/vault --ignore-scripts --no-audit --no-fund
node demo/judge/vault/build.mjs
```

O resultado fica em `demo/judge/dist/farol-26.html`. No Windows, abra esse arquivo no Edge ou no Chrome. Para repetir o teste de interface com Python, instale Playwright e seu Chromium ou passe o executável existente por `--chromium`. Execute `python demo/judge/vault/check_browser.py`. O teste usa um contexto novo e offline, telas larga e estreita, controles reais, pausa e reinício.

| Etapa | Conferência feita agora | Origem e limite |
|---|---|---|
| PKI privada | Hash dos bytes do pacote, política, CSR, 2/3 negado com zero certificados, três assinaturas para o mesmo pedido, X.509 e recusa de reutilização. | A conexão TLS foi feita em loopback no gerador do PR #7. O gerador só exporta após conferir cadeia, nome, HTTP 200 e impressão digital. O HTML não reabre o serviço nem contém um transcript TLS assinado. [Gerador fixado](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/blob/4069503b6f2de3667f5cab406b2e3f580294b45f/demo/issuance_case.py) · [Pins independentes](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/blob/344a84cb45cccf0344b4a8e5ab2e83f622eff3e7/demo/judge/issuance-pins.json) |
| Armazenamento | A edição entregue indica **Não verificado**. | Somente um aceite real do proprietário pode fornecer os metadados da geração e o digest da releitura. |
| Auditoria | ML-DSA-65 verifica a mensagem assinada do ensaio nativo e recusa a cópia com um dígito do desafio alterado. | Os pins e a cabeça do histórico são os do ensaio PQC anterior. A assinatura não vincula o objeto deste cofre. A origem KMS é relatada pelo operador. A verificação portátil usa a implementação pública `@noble/post-quantum`. |

O ensaio de emissão, a CMEK simétrica e a assinatura pós-quântica usam chaves e autorizações diferentes. O quórum da CA não é uma regra de acesso do Cloud Storage.

## Opcional · Aceite do objeto no ambiente do proprietário

**Escopo a aprovar antes de qualquer gravação.** O proprietário identifica o projeto e bucket de teste dedicados e a CryptoKey simétrica existente, confirma a localização e o acesso já concedido ao agente de serviço do Storage. Se o objeto ainda não existir, a aprovação deve mencionar **uma criação exclusiva** de `farol-26/issuance-case.json`, com esta chave, para os 9.163 bytes do PR #7, seguida da consulta dos metadados e de uma leitura da mesma geração. O SHA-256 esperado é `1c615b76986d07c06d7d5cef4995eae5f6a95f136062c7eb97c6c68915d6d9d2`. Confirme que a operação cabe no ambiente já aprovado sem gasto adicional. Se qualquer condição faltar, mantenha **Não verificado**.

**Preflight somente leitura.** No Cloud Shell ou CLI privado do proprietário, use credenciais de aplicação já disponíveis a `google-auth` e `requests`. Defina `WARDEN_PROJECT`, `WARDEN_BUCKET` e `WARDEN_KEY` com os identificadores privados aprovados. A chave tem o formato `projects/PROJETO/locations/LOCAL/keyRings/ANEL/cryptoKeys/CHAVE`. O programa faz GET apenas aos recursos nomeados para conferir projeto, bucket, local e finalidade simétrica da chave existente com primária habilitada. Essa consulta não testa gravação nem comprova que o bucket seja dedicado ou que o agente tenha permissão de uso. As credenciais permanecem no ambiente autenticado.

```sh
python demo/vault_storage.py preflight --project "$WARDEN_PROJECT" \
  --bucket "$WARDEN_BUCKET" --kms-key "$WARDEN_KEY"
```

**Apenas após aprovação explícita do objeto.** Se ele já existir, use sua geração conhecida e passe diretamente à releitura. Para uma nova criação aprovada no Cloud Shell, execute o comando condicional abaixo a partir da raiz do repositório. Ele usa o arquivo fixo do checkout e exige o digest esperado e a ausência de objeto ativo. Guarde a geração retornada. Uma resposta incerta exige conferir a geração antes de considerar qualquer nova tentativa.

```sh
(cd demo/judge && printf '%s  issuance-case.json\n' \
  '1c615b76986d07c06d7d5cef4995eae5f6a95f136062c7eb97c6c68915d6d9d2' | sha256sum --check) && \
gcloud storage cp demo/judge/issuance-case.json "gs://$WARDEN_BUCKET/farol-26/issuance-case.json" \
  --encryption-key="$WARDEN_KEY" --if-generation-match=0 --print-created-message
```

**Registrar a releitura.** Defina `WARDEN_GENERATION` com a geração observada. O programa repete o preflight, compara o nome e o tamanho do objeto, verifica o campo `kmsKeyName` da **geração** e lê os bytes dessa mesma geração com autenticação normal. Ele grava um JSON novo somente após conferir o digest. Um erro de permissão, identificação, chave ou digest interrompe o aceite. Nenhuma chamada do programa altera a nuvem.

```sh
python demo/vault_storage.py record --project "$WARDEN_PROJECT" \
  --bucket "$WARDEN_BUCKET" --kms-key "$WARDEN_KEY" --generation "$WARDEN_GENERATION" \
  --output public-storage-report.json
node demo/judge/vault/build.mjs public-storage-report.json
```

O esquema fechado `warden-storage-cmek-v1` exporta `source`, o nome sintético `asset`, `generation`, `size_bytes`, `asset_sha256`, `readback_sha256`, o SHA-256 do `kmsKeyName` observado (`kms_key_sha256`) e `kms_key_version` (ou `null` quando omitida pelo serviço). Inclui também o identificador `schema`. O build aceita apenas esses campos e valores compatíveis com o ativo fixado. Não exporte identificadores de projeto, bucket ou chave, tokens ou metadados brutos. A consistência de um relatório fornecido é verificável localmente; a observação do provedor continua atribuída ao operador. [CMEK do Cloud Storage](https://docs.cloud.google.com/storage/docs/encryption/customer-managed-keys) · [Metadados de objetos](https://docs.cloud.google.com/storage/docs/json_api/v1/objects)

## Opcional · Discos e chaves do próprio avaliador

- Para um disco de teste existente e autorizado, confira em separado a referência CMEK de `diskEncryptionKey.kmsKeyName` na descrição do disco. Relacione o disco ao volume montado e compare o SHA-256 de um arquivo sintético conhecido com o da releitura nesse volume. Preserve a identidade do disco e o digest na observação. O registro de reinício anterior, por si, não demonstra CMEK.
- O avaliador pode executar o preflight em seu Cloud Shell/CLI com uma chave simétrica própria já existente. Uma experiência distinta com importação só faria sentido sob autorização adicional e com material descartável encapsulado para o destino de importação do KMS. Não use chaves de TLS ou de PQC, não cole material de chave no portal e não importe nada para o percurso principal.
