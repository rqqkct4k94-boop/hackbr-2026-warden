# Warden — Hack Brasil 2026

**Quem controla a confiança digital da sua organização?**

Warden é um protótipo de módulo de segurança definido por software (SDSM) para governança de uma PKI privada: três custodiantes distintos autorizam a mesma solicitação, e um verificador independente confere a evidência criptográfica. O laboratório utiliza exclusivamente uma organização e identidades sintéticas.

## Experimente agora

- **[Portal público de avaliação](https://hackbr-2026-warden-p0.royalcrafter.workers.dev/)** — abra sem login, selecione *Verificar amostra* e depois *Testar alteração local*. A primeira ação valida a prova; a segunda demonstra a rejeição de uma amostra modificada.
- [Relatório registrado do laboratório GCP](demo/judge/recorded-cloud.json) — quatro validadores Besu/QBFT com três pares cada, duas conexões HTTPS com certificados distintos, sete eventos de auditoria, duas operações autorizadas e uma âncora confirmada por quatro recibos.
- [Prova e limites de segurança](demo/P0.md) — arquitetura, reprodução, testes e distinção entre evidência registrada em nuvem e a cerimônia local usada no verificador.
- [Roteiro de avaliação](demo/JUDGE_REHEARSAL.md) — demonstração em português de até três minutos.

## Estado verificado — 23/11/2026

| Gate | Evidência |
|---|---|
| Autorizações 3/3, X.509 e TLS | Testes locais reais; autorização criptográfica distinta e negação quando a política não é satisfeita. |
| Laboratório isolado GCP / Besu | Execução registrada reportada pelo operador: quatro validadores, duas conexões TLS e âncora confirmada. Não é uma consulta ao RPC privado pelo portal. |
| Portal público | HTTPS e verificação no navegador confirmados; amostra alterada rejeitada. A amostra local e o relatório GCP correspondem a cerimônias distintas. |
| Parada por inatividade | Cinco VMs observadas desligadas; a execução posterior também reportou discos preservados. A verificação completa após reinício ainda está pendente. |
| Custódia em ambientes independentes, KMS e HSM | Em evolução; não foram validadas emissão remota por três ambientes independentes, integração KMS real ou equivalência/certificação HSM. |

**Limite importante:** Warden é uma demonstração de autorização e evidência criptográfica em software. Não é um HSM certificado, não demonstra resistência a um host de assinatura comprometido e não reivindica garantias formais de assinatura limiar/MPC. Os serviços privados e segredos de custódia não estão expostos ao público.

## Reproduzir

O código foi criado para esta competição. As instruções completas de testes e os limites conhecidos estão em [demo/P0.md](demo/P0.md). A documentação de provisionamento isolado autorizado pelo proprietário está em [demo/CLOUD_SHELL.md](demo/CLOUD_SHELL.md).

A solução usa Python, X.509, TLS, Hyperledger Besu e um verificador de evidência executado no navegador. O laboratório de nuvem e o portal público têm escopos separados. Não são usados dados pessoais reais de terceiros.

**Desenvolvimento:** ferramentas de IA foram utilizadas no desenvolvimento, documentação e revisão desta demonstração, sob supervisão do participante.
