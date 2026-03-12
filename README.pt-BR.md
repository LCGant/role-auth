# Servico de Auth

[Read in English](README.md) | [Raiz do projeto](../../README.pt-BR.md)

`role-auth` e o servico de identidade da plataforma. Ele controla credenciais locais, sessoes, binding de dispositivo, MFA, login OAuth, reset de senha e verificacao de email.

## Escopo principal

- cadastro e login local
- sessoes opacas com validacao por dispositivo
- MFA TOTP e backup codes
- login OAuth e link de contas
- verificacao de email
- reset de senha
- introspeccao interna de sessao para chamadores confiaveis

## Modelo de seguranca

O servico foi desenhado para ser a fonte de verdade do estado de autenticacao.

- sessoes sao opacas e armazenadas por hash
- token de dispositivo e separado do token de sessao
- fluxos de MFA e reauth rotacionam ou reemitem sessao quando necessario
- contas locais precisam verificar email antes de ficarem totalmente ativas
- endpoints internos usam tokens dedicados
- fluxos de browser e nao-browser sao tratados de forma diferente para CSRF

## Integracoes internas

- envia pedidos de entrega de verificacao e reset para `notification`
- encaminha eventos de auditoria para `audit`
- serve introspeccao de sessao para `pep` e outros servicos internos confiaveis

## Estado atual

Este servico ja cobre a parte dificil do nucleo de autenticacao e e um bom ponto de partida tecnico. Ainda faltam integracoes especificas de producao, como provedores de email mais maduros, fluxos operacionais e disciplina de rollout por ambiente.

## Notas para contribuidores

- trate este servico como codigo sensivel de seguranca
- prefira comportamento fail-closed
- teste auth, sessao, MFA, OAuth e reset depois de qualquer mudanca relevante
- leia `docs/SECURITY_INVARIANTS.md` antes de alterar logica de sessao ou reauth

