# Central de Certificados

Site estático que reúne, em uma única interface, o **conversor de certificados** (PFX/P12 ↔ PEM, CRT, CER, KEY, JKS) e a **geração de CSR + chave privada**, além de um inspetor de certificados.

A interface segue o **Material Design 3**: tokens de cor gerados a partir do teal da marca, escala tipográfica e de forma do M3, campos outlined com label flutuante, tabs primárias, segmented buttons, chips, switches e snackbar. Tema claro e escuro com alternância no cabeçalho (a preferência fica salva no navegador).

Tudo roda **no navegador do usuário**. Não há servidor, backend nem banco de dados: chaves, certificados e senhas nunca saem da máquina. Por isso os arquivos gerados são baixados na hora — não ficam salvos em lugar nenhum.

## As quatro abas

### 1. Converter
Fluxo em três etapas, o mesmo de antes, com melhorias:

- **Origem**: `.pfx`/`.p12` com senha, ou `.pem`/`.crt`/`.cer`/`.der` + chave opcional. Aceita também **DER binário, base64 sem cabeçalho e `.p7b` (PKCS#7)**, e um campo separado para a **cadeia / CA intermediária** (vários arquivos de uma vez).
- **Conteúdo detectado**: cada certificado vira um cartão com subject, issuer, validade, serial e SAN; escolha qual é o leaf e quais entram na exportação. Certificados expirados ganham selo, e o cartão que corresponde à chave privada é marcado.
- **Validação chave ↔ certificado**: o módulo RSA da chave é comparado com o do certificado. Se não baterem, a geração do PFX é bloqueada com explicação — antes o arquivo saía quebrado e só falhava na importação.
- **Saída**: `.PEM`, `.CRT`/`.CER` (PEM ou DER), `.PFX/.P12`, `.JKS` (truststore) e `.KEY`. O PFX agora permite escolher a cifra (**3DES** para compatibilidade com Windows/IIS/Java, ou AES-128/256), monta a cadeia na ordem leaf → intermediária → raiz e mostra o comando OpenSSL equivalente. Os arquivos saem nomeados pelo CN do certificado.

### 2. Gerar CSR + chave
- Subject completo (CN, O, OU, L, ST, C, e-mail) com os tipos ASN.1 corretos (`C` como PrintableString, e-mail como IA5String).
- SAN em chips, com detecção automática de DNS, IP, e-mail e URI; o CN entra automaticamente.
- **Importação de arquivo `.cnf` do OpenSSL** — veja abaixo.
- RSA 2048/3072/4096, assinatura SHA-256/384/512, chave em PKCS#8 ou PKCS#1, opcionalmente cifrada com AES-256.
- Download do `.csr` e do `.key`, CSR decodificado na tela e comando OpenSSL equivalente.
- Geração em Web Worker: uma chave de 2048 bits sai em menos de 1 s sem travar a página.
- Botão **"Usar esta chave no conversor"**: leva a chave recém-gerada para a aba Converter, para montar o PFX assim que a AC devolver o certificado — sem salvar a chave em disco no meio do caminho.

### 3. Inspecionar
Decodifica certificado, cadeia, CSR ou chave: subject, emissor, validade com alerta de expiração, SAN, tamanho da chave, serial e fingerprint SHA-256.

### 4. Ajuda
Documentação embutida, com navegação por tópicos e destaque do tópico atual conforme a rolagem. Cobre o **processo completo** (linha do tempo das sete etapas, diferença entre AC interna e pública, modelo de chamado, renovação), o uso de cada aba, formatos de arquivo, instalação por plataforma, problemas comuns e segurança.

Cada etapa das outras abas tem um botão **Ajuda** que abre o tópico correspondente e oferece um botão de voltar para de onde a pessoa veio. A [wiki do repositório](https://github.com/tamanakalucas/Conversor-Certificados/wiki) segue como referência longa; a aba Ajuda responde "o que eu faço agora" sem tirar ninguém da tela.

## Detalhes de usabilidade

- **Áreas de arrastar e soltar** no lugar dos campos de arquivo nativos, com nome do arquivo e botão de remover depois da seleção.
- **SAN por chips**: digite e pressione Enter; o tipo (DNS, IP, email, URI) é detectado e mostrado em cada chip. Colar uma lista separada por vírgula ou quebra de linha cria vários de uma vez. O CN aparece como chip fixo, deixando claro que entra no CSR automaticamente.
- **Erros no campo certo**: campo obrigatório em branco ou país inválido destacam o próprio campo, além da mensagem.
- **Snackbar** confirma download, cópia e troca de tema sem empurrar o conteúdo da página.
- **Barra de progresso** durante a geração da chave, com o tamanho em bits no próprio botão.
- **Botão Recomeçar** no conversor limpa arquivos, senhas e seleções de uma vez.
- Alvos de toque de 40–48px, foco visível em tudo navegável por teclado, e role/aria-selected nas tabs e nos cartões de formato.

## Importar dados de um arquivo `.cnf`

Na aba **Gerar CSR + chave** → **Carregar arquivo .cnf**, é possível enviar (ou colar) um arquivo de configuração do OpenSSL em vez de digitar campo a campo. Os campos do formulário são preenchidos e ficam editáveis antes de gerar.

Formatos aceitos:

| Formato | Exemplo |
|---|---|
| `.cnf` com `prompt = no` | `[ req_distinguished_name ]` + `CN = exemplo.com.br` |
| `.cnf` em modo prompt | usa os valores `*_default` (`commonName_default = exemplo.com.br`) |
| SAN por seção | `subjectAltName = @alt_names` + `[ alt_names ]` com `DNS.1`, `IP.1`, … |
| SAN inline | `subjectAltName = DNS:a.com.br, DNS:www.a.com.br, IP:10.0.0.5` |
| Linha de subject | `/C=BR/ST=SP/O=Empresa/CN=exemplo.com.br` |
| Pares soltos | `CN = exemplo.com.br` (um por linha, sem seções) |

Também são lidos `default_bits` e `default_md`; se o valor não estiver entre as opções da tela (2048/3072/4096 e SHA-256/384/512), o campo é mantido e um aviso é exibido. Nomes longos (`commonName`, `organizationName`…), abreviados (`CN`, `O`…) e numerados (`0.organizationName`) são todos reconhecidos, e comentários com `#` são ignorados.

Exemplo completo:

```ini
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
C  = BR
ST = SP
L  = São Paulo
O  = Minha Empresa LTDA
OU = TI
CN = exemplo.com.br

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = exemplo.com.br
DNS.2 = www.exemplo.com.br
IP.1  = 192.168.0.10
```

## Publicação

O site é estático — não há build nem dependência de servidor. O GitHub Pages deste repositório já
publica de `main` / raiz, então o merge deste PR atualiza direto
<https://tamanakalucas.github.io/Conversor-Certificados/>.

Todos os caminhos são relativos, então funciona tanto no subcaminho `/Conversor-Certificados/` quanto
em domínio próprio. O `.nojekyll` evita o processamento do Jekyll.

## Rodar localmente

Precisa ser via HTTP (o Web Worker de geração de chave não carrega em `file://`; há fallback, só fica mais lento):

```bash
npx http-server . -p 4173
```

## Estrutura

```
.
├── index.html              # header, 4 abas (inclusive a ajuda) e os painéis
├── assets/
│   ├── styles.css          # tokens e componentes Material Design 3 (tema claro + escuro)
│   └── app.js              # toda a lógica, sem build
├── vendor/
│   ├── forge.min.js        # node-forge 1.4.0 (BSD/GPL) — RSA, PKCS#10, PKCS#12, PKCS#7
│   ├── prime.worker.min.js # worker de geração de primos
│   └── forge-LICENSE.txt
└── .nojekyll
```

O node-forge é servido localmente (versão 1.4.0, mais recente que a 1.3.1 do CDN usada antes): o site funciona offline depois de carregado e não faz nenhuma requisição de rede além das fontes do Google Fonts (Roboto na interface, IBM Plex Mono em PEM e comandos), ambas com fallback para as fontes do sistema. Os ícones são SVG inline — sem biblioteca externa.

## Limitações

- **Apenas chaves RSA.** ECDSA não é suportado — o node-forge não assina CSR nem monta PKCS#12 com curvas elípticas.
- O `.JKS` gerado é um **truststore** (somente certificados). JKS com chave privada usa algoritmo proprietário da Oracle; a tela mostra o comando `keytool` equivalente.
- O PFX é gerado com MAC SHA-1 (padrão do node-forge, aceito pela maioria dos servidores e pelo OpenSSL 3.x).

## Verificação

A saída foi conferida contra o **OpenSSL 3.5** real:

```bash
openssl req -in exemplo.csr -noout -text -verify     # "self-signature verify OK", SAN e acentos corretos
openssl pkcs12 -info -in exemplo.pfx -nodes          # chave + cadeia na ordem certa + friendlyName
```
