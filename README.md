# Firewall Simulator

Um simulador de firewall de rede com inspecao stateful de pacotes, operando nas camadas 3 e 4 do modelo OSI. O sistema avalia pacotes TCP/UDP com base em regras configuraveis e usa uma tabela de estados para acelerar fluxos ja autorizados.

---

## Indice

- [Como funciona](#como-funciona)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Como rodar](#como-rodar)
- [Como rodar os testes](#como-rodar-os-testes)
- [Exemplo de teste](#exemplo-de-teste)
- [Entendendo a saida](#entendendo-a-saida)
- [O que e stateful](#o-que-e-stateful)

---

## Como funciona

O firewall analisa cada pacote usando os campos da 5-tupla:

- IP de origem
- IP de destino
- Porta de origem
- Porta de destino
- Protocolo

O fluxo de decisao e:

1. Consultar a `StateTable`.
2. Se a conexao ja estiver ativa, liberar o pacote pelo `fast_path`.
3. Se nao estiver, percorrer as regras em ordem.
4. Ao encontrar a primeira regra compativel, aplicar a acao.
5. Se a acao for `ALLOW`, registrar a conexao na `StateTable`.
6. Se nenhuma regra casar, aplicar `default_action = BLOCK`.

O `Firewall` retorna uma decisao estruturada por pacote, contendo:

- `action`: `ALLOW` ou `BLOCK`
- `matched_rule`: a regra que casou, quando existir
- `decision_source`: `fast_path` ou `slow_path`

Isso deixa a logica de decisao concentrada no engine, enquanto o `main.py` apenas exibe o resultado.

---

## Estrutura do projeto

```text
firewall-simulator/
|-- app/
|   |-- main.py
|   |-- data/
|   |   |-- packets.json
|   |   `-- rules.json
|   |-- engine/
|   |   |-- firewall.py
|   |   |-- matcher.py
|   |   `-- state_table.py
|   |-- models/
|   |   |-- connection.py
|   |   |-- decision.py
|   |   |-- enums.py
|   |   |-- packet.py
|   |   `-- rule.py
|   |-- parser/
|   |   |-- packets_parser.py
|   |   |-- rules_parser.py
|   |   `-- validators.py
|   `-- simulation/
|       `-- packet_generator.py
|-- tests/
|   `-- test_firewall.py
`-- README.md
```

### Responsabilidade dos modulos

- `models/`: entidades centrais do dominio.
- `parser/`: leitura e validacao de arquivos JSON.
- `engine/`: motor de decisao do firewall.
- `tests/`: verificacao automatica dos cenarios principais.

---

## Como rodar

### Pre-requisitos

- Python 3.10 ou superior

```bash
python --version
```

### Executando o simulador

Rode este comando na raiz do projeto:

```bash
python -m app.main
```

Tambem funciona:

```bash
python app/main.py
```

---

## Como rodar os testes

Rode este comando na raiz do projeto:

```bash
python -m unittest discover -s tests -v
```

A suite cobre:

- pacote permitido por regra
- pacote bloqueado por regra
- bloqueio por regra padrao
- registro de conexao na `StateTable`
- reaproveitamento do `fast_path`
- validacao de entrada invalida

---

## Configurando regras

Edite `app/data/rules.json`. As regras sao avaliadas de cima para baixo, e a primeira que casar define a acao:

```json
[
  { "action": "BLOCK", "source_ip": "any", "destination_ip": "any", "port": 23, "protocol": "TCP" },
  { "action": "ALLOW", "source_ip": "any", "destination_ip": "any", "port": 80, "protocol": "TCP" },
  { "action": "ALLOW", "source_ip": "any", "destination_ip": "any", "port": 53, "protocol": "UDP" }
]
```

## Configurando pacotes

Edite `app/data/packets.json`. Cada pacote usa a 5-tupla:

```json
[
  {
    "source_ip": "10.0.0.10",
    "destination_ip": "192.168.0.1",
    "source_port": 54321,
    "destination_port": 80,
    "protocol": "TCP"
  }
]
```

---

## Exemplo de teste

O arquivo padrao `packets.json` inclui 6 pacotes que exercitam os cenarios principais:

```json
[
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"},
  {"source_ip": "10.0.0.11", "destination_ip": "192.168.0.1", "source_port": 54322, "destination_port": 23, "protocol": "TCP"},
  {"source_ip": "10.0.0.12", "destination_ip": "8.8.8.8", "source_port": 54323, "destination_port": 53, "protocol": "UDP"},
  {"source_ip": "10.0.0.13", "destination_ip": "192.168.0.1", "source_port": 54324, "destination_port": 22, "protocol": "TCP"},
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"},
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"}
]
```

Os pacotes 5 e 6 repetem o pacote 1 para demonstrar o `fast_path`.

Execute:

```bash
python -m app.main
```

### Saida esperada

```text
=================================================================
PROTOCOLO ORIGEM                 DESTINO                ACAO   VIA
=================================================================
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  RULE MATCHING (slow path)
TCP    10.0.0.11:54322        192.168.0.1:23         BLOCK  RULE MATCHING (slow path)
UDP    10.0.0.12:54323        8.8.8.8:53             ALLOW  RULE MATCHING (slow path)
TCP    10.0.0.13:54324        192.168.0.1:22         BLOCK  RULE MATCHING (slow path)
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  STATE TABLE (fast path)
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  STATE TABLE (fast path)
=================================================================
Conexoes ativas na State Table: 2
```

---

## Entendendo a saida

| Pacote | Resultado | Via | Explicacao |
|---|---|---|---|
| `10.0.0.10 -> :80 TCP` | ALLOW | slow path | Casou com a regra de porta 80 e foi registrado na tabela. |
| `10.0.0.11 -> :23 TCP` | BLOCK | slow path | Casou com a regra de bloqueio da porta 23. |
| `10.0.0.12 -> :53 UDP` | ALLOW | slow path | Casou com a regra de porta 53 e foi registrado na tabela. |
| `10.0.0.13 -> :22 TCP` | BLOCK | slow path | Nenhuma regra casou; aplicou o bloqueio padrao. |
| `10.0.0.10 -> :80 TCP` | ALLOW | fast path | A conexao ja estava ativa na `StateTable`. |
| `10.0.0.10 -> :80 TCP` | ALLOW | fast path | Mesmo fluxo, liberado sem reavaliar regras. |

Somente conexoes autorizadas entram na `StateTable`.

---

## O que e stateful

No modo stateless, cada pacote seria analisado do zero, mesmo que pertencesse a uma conexao ja conhecida. Isso simplifica a implementacao, mas repete trabalho.

No modo stateful, o firewall memoriza conexoes autorizadas usando a 5-tupla:

```text
(IP origem, IP destino, porta origem, porta destino, protocolo)
```

Assim, o primeiro pacote de um fluxo passa pelo `slow_path`, e os proximos podem ser aceitos pelo `fast_path`.

### Observacao didatica

Este projeto implementa uma versao didatica de comportamento stateful baseada em rastreamento de fluxo pela 5-tupla. Ele nao modela estados TCP completos, como `SYN`, `ACK`, `FIN` e `RST`.
