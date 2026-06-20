# Project instructions

## Pull requests

- **NUNCA** abrir, fazer push ou direcionar um PR para o upstream da Anthropic (`anthropics/claude-code-security-review`).
- Todos os PRs devem ter como base o fork do próprio usuário: `uamartins/claude-code-security-review`.
- Ao usar `gh pr create`, sempre passar `--repo uamartins/claude-code-security-review` explicitamente (o padrão do `gh` aponta para o repositório pai/upstream em forks).
- Da mesma forma, `git push` deve ir para `origin` (o fork), nunca para `upstream`.
