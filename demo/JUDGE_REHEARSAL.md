# Warden — roteiro de demonstração (até 3 minutos)

**Mensagem central:** quem controla a confiança digital da sua organização? Warden exige três aprovações criptográficas distintas antes de uma decisão crítica e produz uma prova verificável por terceiros.

## Roteiro (português)

**0:00–0:30 — problema.** Bancos, hospitais, empresas e governos dependem de certificados digitais para autenticar serviços. Se a decisão de emissão concentra poder demais em um único operador ou sistema, toda a organização herda esse risco. Warden demonstra outra forma de governar essa confiança: autorização unânime e evidência verificável.

**0:30–1:05 — arquitetura.** Cada serviço tem sua própria chave e solicita um certificado à autoridade privada da organização. Três custodiantes distintos precisam assinar a mesma solicitação, vinculada ao nome, à chave pública e à validade. A autoridade rejeita autorizações insuficientes. O histórico registra exatamente o que foi autorizado, e sua cabeça pode ser registrada em uma rede privada Besu de quatro validadores.

**1:05–1:50 — demonstração principal.** No painel privado, mostre os dois sites sintéticos e acione a verificação HTTPS: ambos passam, mas usam certificados diferentes. Mostre as duas operações aprovadas, o histórico e o relatório registrado dos quatro validadores, todos com três peers. A âncora foi confirmada por quatro recibos. Se o teste de custódia distribuída tiver terminado, mostre também as três assinaturas de presença dos respectivos ambientes — explique que isso comprova a posse das chaves nesses ambientes, e não três operadores humanos independentes. Não diga que uma emissão distribuída foi exercitada se apenas a presença foi testada.

**1:50–2:25 — experiência do avaliador.** Abra o portal de verificação, pressione “Verificar amostra”, e mostre as assinaturas, certificados e trilha de auditoria validados no próprio navegador. Depois, pressione “Testar alteração local”: a verificação rejeita a prova alterada. A amostra é de uma cerimônia sintética local separada; o relatório de nuvem registra outra execução, não uma consulta pública ao RPC privado. O avaliador pode baixar a evidência e os pins e verificar por conta própria.

**2:25–3:00 — impacto e próximos passos.** Esse controle interessa a organizações que precisam responder a uma pergunta verificável: quem autorizou nossa confiança digital? O modelo pode evoluir para dispositivos HSM, custódia com operadores distintos e integração com ambientes de identidade existentes. O protótipo demonstra uma autoridade privada controlada por três assinaturas; não é um HSM certificado nem um protocolo de assinatura limiar com garantia formal. Nossa proposta é tornar a governança da confiança uma evidência técnica, e não apenas uma promessa.

## Evidências obrigatórias antes de gravar a versão final

- Confirmar relatório GCP com quatro validadores, TLS e âncora; não substituir por testes simulados.
- Confirmar gate de 10 minutos, preservação dos discos e reinício antes de afirmar essa propriedade em nuvem.
- Abrir o portal publicado com HTTPS válido; caso ainda não publicado, usar a prévia local e não anunciar uma URL pública.
- Testar ambas as ações interativas do verificador; manter à mão o pacote de evidência público.
- Para a custódia, distinguir o processo local de três autorizações, o teste de presença nos três VMs e uma futura cerimônia real de emissão/renovação entre os VMs.
- Se a infraestrutura estiver desligada por inatividade, o operador autorizado inicia somente o grupo isolado e espera a verificação real, que pode sofrer atrasos na inicialização. Não expor o serviço de assinatura, chaves, compartilhamentos de custódia ou RPC.
- Mostrar código original público e resultados de testes. Não incluir nomes, credenciais, endereços privados ou dados de organizações reais na gravação.
