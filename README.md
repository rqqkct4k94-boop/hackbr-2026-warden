# Warden — Hack Brasil 2026

[![Testes de evidência](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/actions/workflows/verify.yml/badge.svg)](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/actions/workflows/verify.yml)

## FAROL-26 · Abrir um cofre de evidências

O [modo guiado do júri](demo/COFRE_FAROL.md) reúne a emissão do PR #7, o estado da proteção do objeto e um teste de alteração da prova ML-DSA. Para a prévia privada, abra `farol-26.html` sem login. O arquivo pode ser reproduzido com o build documentado e executa offline. Nesta edição, o armazenamento externo está **não verificado**.

## Um pedido, duas decisões e um certificado verificável

O serviço fictício `alpha.warden-demo.invalid` pede um certificado. Com duas aprovações válidas, a CA registra a recusa e zero certificados para o serviço. A terceira identidade assina o **mesmo pedido** e a CA emite um X.509. O certificado contém o SHA-256 do pedido, que inclui o CSR e o hash da política. Uma tentativa de reutilizar a autorização é recusada.

### Conferir sem conta

1. Na raiz deste checkout, execute `node demo/judge/build.mjs` com Node 22+ e abra `demo/judge/dist/standalone.html` no navegador. Essa é a edição local da página inicial do júri e funciona offline.
2. Clique em **Verificar emissão 2/3 → 3/3**. Confira os signatários, o ID do pedido, o hash gravado no X.509 e a impressão digital do certificado. Em **Testar aprovação alterada**, a troca de uma assinatura deve resultar em recusa.
3. Use **Baixar pacote de emissão** e depois **Conferir uma cópia salva**. A página reaplica os pins desta edição ao arquivo selecionado. O [pacote JSON público](demo/judge/issuance-case.json) também está neste repositório.

**Referência de confiança.** Retenha os [pins deste commit específico](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/blob/344a84cb45cccf0344b4a8e5ab2e83f622eff3e7/demo/judge/issuance-pins.json) a partir de um checkout ou canal em que você já confia. A cerimônia fixa a raiz e o manifesto antes do pedido, e a cabeça de auditoria após a recusa do replay. O SHA-256 do arquivo de pins desta edição é `c5dd1c2621db69ca6ab07203c363f2d393d29b5b9b1910617245e73af9c22a26`. Quem distribui um pacote adulterado pode fornecer também outros pins. A verificação depende da referência guardada e de uma cópia confiável do verificador.

| O que conferir | Evidência | Alcance |
|---|---|---|
| Política 3/3, pedido e duas decisões | No JSON, `manifest.issuance_policy` define a política. `events[1]` contém o pedido e o CSR. Em `events[2]` estão as duas assinaturas e a contagem zero observada pela CA. | Uma CA local descartável, três chaves Ed25519 sintéticas. O histórico fixado preserva a observação feita pelo software. |
| Certificado e uso único | `events[3]` contém as três aprovações, o PEM do certificado, o serial e a impressão digital. A assinatura da CA cobre a extensão com o hash do pedido. `events[4]` registra a recusa de reutilização. | O verificador confere a assinatura da raiz e do certificado, a chave do CSR e o nome DNS. O gerador também testa uma conexão HTTPS em loopback. |
| Ensaio público anterior | [Portal publicado](https://hackbr-2026-warden-p0.royalcrafter.workers.dev/) e [console SDSM](https://hackbr-2026-warden-p0.royalcrafter.workers.dev/console). | A versão publicada demonstra a amostra anterior e o ensaio no navegador. O novo caso foi validado na compilação local. |

### Reproduzir a emissão

Em um ambiente Python com `python -m pip install -r demo/requirements.txt`, execute `python demo/issuance_case.py /tmp/warden-minha-cerimonia`, indicando um diretório novo. O gerador faz o pedido, testa a negativa, emite o certificado, testa o replay e verifica o site HTTPS descartável. Ele exporta somente o pacote público e o registro de confiança dessa execução. Cada nova cerimônia tem suas próprias chaves e seus próprios pins.

Para verificar sem navegador, confira os valores abaixo na sua referência já guardada e execute o comando.

```sh
python demo/warden_cli.py verify --evidence demo/judge/issuance-case.json \
  --root-pin 2b2bf11f3f9d1c0f196a8a0fb4b486f2c3d962259b290f5394a54fda471bd307 \
  --manifest-pin d5444304f083ffeeeefaccf366a5f323c7ca5c826d8c4314ce46ab4a6d6f7b8a \
  --audit-head 024a215fd51e5c17fb2d4f689f3cc127d0f4b5966d8a88c0c97c56d4333821eb
```

Em uma cerimônia própria, substitua os três pins pelos valores que você guardou. Os testes podem ser reproduzidos com `(cd demo && python -m unittest discover)` e, após o build, `node --test demo/judge/test_*.mjs demo/test_quantum_authority.mjs`. O [teste do fluxo no Chromium](demo/judge/check_issuance_browser.py) usa Playwright. A [execução histórica de CI](https://github.com/rqqkct4k94-boop/hackbr-2026-warden/actions/runs/45231683625) documenta uma revisão anterior.

### Evidência suplementar

- **GCP e Besu.** O operador registrou as cinco VMs encerradas após 728,558 s de observação. Após reiniciar, confirmou os cinco discos, quatro validadores, quatro recibos correspondentes e as impressões digitais de dois certificados TLS. A medição inclui a latência do provedor. O portal lê o registro fornecido pelo operador. [Ciclo de vida](demo/judge/recorded-lifecycle.json) · [Execução inicial](demo/judge/recorded-cloud.json)
- **PQC.** A página publicada em 25/11 permite verificar a assinatura nativa ML-DSA-65 e sua rejeição após alteração. A experiência ML-KEM-768 está descrita em um relatório assinado pelo operador. A origem da chave depende desse relato. [Abrir /quantum](https://hackbr-2026-warden-p0.royalcrafter.workers.dev/quantum) · [Registro da versão publicada](demo/judge/recorded-pqc-release.json)
- **Limites.** Continuam sem comprovação a emissão X.509 por um assinador externo não exportável, a imposição de 3/3 pelo KMS, a custódia independente em produção, a emissão multinuvem e o desbloqueio IBM vinculado ao pedido. O registro disponível de KMS se refere à experiência PQC. [Critérios e escopo](demo/PENDING_GATES.md) · [Arquitetura e limites de segurança](demo/P0.md)

A solução usa Python, X.509, TLS, Hyperledger Besu e um verificador de evidência executado no navegador. O laboratório de nuvem e o portal público têm escopos separados. Não são usados dados pessoais reais de terceiros.

**Desenvolvimento:** ferramentas de IA foram utilizadas no desenvolvimento, documentação e revisão desta demonstração, sob supervisão do participante.
