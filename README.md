# 🔥 Firewall Simulator

Um simulador de firewall de rede com **Stateful Packet Inspection**, operando nas camadas 3 (Rede) e 4 (Transporte) do modelo OSI. O sistema analisa cabeçalhos de pacotes TCP/UDP e toma decisões de segurança baseadas em regras configuráveis — com memória de conexões ativas para performance e inteligência.

---

## 📋 Índice

- [Como funciona](#-como-funciona)
- [Estrutura do projeto](#-estrutura-do-projeto)
- [Como rodar](#-como-rodar)
- [Exemplo de teste](#-exemplo-de-teste)
- [Entendendo a saída](#-entendendo-a-saída)
- [O que é Stateful](#-o-que-é-stateful)

---

## ⚙️ Como funciona

O firewall inspeciona cada pacote extraindo quatro parâmetros do cabeçalho:

- **IP de Origem e Destino** — identifica quem envia e quem recebe
- **Porta de Destino** — determina qual serviço está sendo acessado
- **Protocolo** — TCP (orientado a conexão) ou UDP (orientado a velocidade)

Com esses dados, o sistema toma uma decisão: **ALLOW** ou **BLOCK**.

O fluxo de decisão segue dois caminhos:

```
Pacote chega
      │
      ▼
┌─────────────────────────┐
│   StateTable.lookup()   │  ← consulta O(1) via Hash Table
│   Conexão conhecida?    │
└────────┬────────────────┘
    SIM  │  NÃO
         │         ▼
  ALLOW  │    Percorre lista de regras (First Match)
(fast    │         │
 path)   │    ALLOW → registra na State Table
         │    BLOCK → descarta (não registra)
         │    (sem match) → default: BLOCK
```

---

## 📁 Estrutura do projeto

```
firewall_simulator/
│
├── app/
│   ├── main.py                   # Ponto de entrada da aplicação
│   │
│   ├── data/
│   │   ├── packets.json          # Pacotes de entrada para simulação
│   │   └── rules.json            # Regras de filtragem configuráveis
│   │
│   ├── models/                   # Entidades do sistema (objetos tipados)
│   │   ├── packet.py             # Representa um pacote de rede (5-tupla)
│   │   ├── rule.py               # Representa uma regra de firewall
│   │   ├── enums.py              # Enums: Protocol (TCP/UDP) e Action (ALLOW/BLOCK)
│   │   ├── decision.py           # Resultado da avaliação de um pacote
│   │   └── connection.py         # ConnectionKey e ConnectionState (Stateful)
│   │
│   ├── engine/                   # Cérebro do firewall
│   │   ├── firewall.py           # Orquestrador: coordena State Table + Rule Matching
│   │   ├── matcher.py            # Compara parâmetros do pacote contra uma regra
│   │   └── state_table.py        # Hash Table de conexões ativas (fast path)
│   │
│   └── parser/                   # Camada de leitura e validação de dados
│       ├── packets_parser.py     # Lê packets.json e converte em objetos Packet
│       ├── rules_parser.py       # Lê rules.json e converte em objetos Rule
│       └── validators.py         # Valida IPs, portas, protocolos e ações
│
├── .gitignore
└── README.md
```

### Responsabilidade de cada módulo

**`models/`** — define a linguagem comum do sistema. Todos os outros módulos trocam objetos tipados (`Packet`, `Rule`, `ConnectionState`), nunca dicionários ou strings cruas.

**`parser/`** — tradutor entre o mundo externo (JSON) e o mundo interno (objetos Python). Se no futuro as regras vierem de um banco de dados ou API, apenas este módulo precisa mudar.

**`engine/`** — o cérebro. O `matcher.py` sabe comparar um pacote contra uma regra. O `state_table.py` mantém a memória de conexões ativas. O `firewall.py` orquestra tudo: consulta a tabela primeiro, cai no matching só quando necessário.

---

## 🚀 Como rodar

### Pré-requisitos

- Python **3.10 ou superior**

```bash
python3 --version
```

### Rodando

```bash
cd firewall-simulator/app
python3 main.py
```

### Configurando regras

Edite `app/data/rules.json` para definir a política de segurança. As regras são avaliadas **de cima para baixo** — a primeira que casar com o pacote define a ação:

```json
[
  { "action": "BLOCK", "source_ip": "any", "destination_ip": "any", "port": 23,  "protocol": "TCP" },
  { "action": "ALLOW", "source_ip": "any", "destination_ip": "any", "port": 80,  "protocol": "TCP" },
  { "action": "ALLOW", "source_ip": "any", "destination_ip": "any", "port": 53,  "protocol": "UDP" }
]
```

### Configurando pacotes

Edite `app/data/packets.json` para simular o tráfego de entrada. Cada pacote precisa dos cinco campos da **5-tupla**:

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

## 🧪 Exemplo de teste

O arquivo `packets.json` padrão inclui 6 pacotes desenhados para validar todos os cenários do firewall:

```json
[
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"},
  {"source_ip": "10.0.0.11", "destination_ip": "192.168.0.1", "source_port": 54322, "destination_port": 23, "protocol": "TCP"},
  {"source_ip": "10.0.0.12", "destination_ip": "8.8.8.8",     "source_port": 54323, "destination_port": 53, "protocol": "UDP"},
  {"source_ip": "10.0.0.13", "destination_ip": "192.168.0.1", "source_port": 54324, "destination_port": 22, "protocol": "TCP"},
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"},
  {"source_ip": "10.0.0.10", "destination_ip": "192.168.0.1", "source_port": 54321, "destination_port": 80, "protocol": "TCP"}
]
```

> Os pacotes 5 e 6 são repetições intencionais do pacote 1 — eles provam que o **fast path Stateful** está funcionando.

Execute:

```bash
python3 main.py
```

### Saída esperada

```
======================================================================
PROTO  ORIGEM                 DESTINO                AÇÃO   VIA
======================================================================
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  RULE MATCHING (slow path)
TCP    10.0.0.11:54322        192.168.0.1:23         BLOCK  RULE MATCHING (slow path)
UDP    10.0.0.12:54323        8.8.8.8:53             ALLOW  RULE MATCHING (slow path)
TCP    10.0.0.13:54324        192.168.0.1:22         BLOCK  RULE MATCHING (slow path)
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  STATE TABLE (fast path)
TCP    10.0.0.10:54321        192.168.0.1:80         ALLOW  STATE TABLE (fast path)
======================================================================
Conexões ativas na State Table: 2
```

---

## 🔍 Entendendo a saída

| Pacote | Porta | Resultado | Via | Explicação |
|--------|-------|-----------|-----|------------|
| `10.0.0.10` → `:80` TCP | 80 | ✅ ALLOW | slow path | Bateu na regra ALLOW porta 80. **Registrado na State Table.** |
| `10.0.0.11` → `:23` TCP | 23 | ❌ BLOCK | slow path | Bateu na regra BLOCK porta 23 (Telnet inseguro). Não registrado. |
| `10.0.0.12` → `:53` UDP | 53 | ✅ ALLOW | slow path | Bateu na regra ALLOW porta 53 (DNS). **Registrado na State Table.** |
| `10.0.0.13` → `:22` TCP | 22 | ❌ BLOCK | slow path | Nenhuma regra casou. Aplicou `default_action = BLOCK`. |
| `10.0.0.10` → `:80` TCP | 80 | ✅ ALLOW | **fast path** ⚡ | 5-tupla já na tabela. Liberado sem percorrer regras. |
| `10.0.0.10` → `:80` TCP | 80 | ✅ ALLOW | **fast path** ⚡ | Idem. |

**`Conexões ativas na State Table: 2`** — apenas as conexões autorizadas são rastreadas: porta 80 (TCP) e porta 53 (UDP). Conexões bloqueadas nunca entram na tabela.

---

## 🧠 O que é Stateful

### O modelo anterior: Stateless

No modelo **Stateless**, o firewall não tem memória. Cada pacote é tratado como um evento completamente novo e isolado. Se uma mesma conexão HTTP enviar 50 pacotes carregando uma imagem, o firewall percorre a lista de regras **50 vezes** — uma para cada pacote — sem saber que todos fazem parte da mesma conversa.

Isso é simples de implementar, mas gera custo computacional repetitivo e não permite entender o contexto de uma comunicação.

### O modelo atual: Stateful

No modelo **Stateful**, o firewall tem memória. Ele rastreia as conexões ativas em uma **State Table** — uma Hash Table onde a chave é a **5-tupla** da conexão:

```
( IP Origem, IP Destino, Porta Origem, Porta Destino, Protocolo )
```

Essa combinação de cinco campos funciona como uma **impressão digital única** de cada conexão na rede.

O fluxo passa a ter dois caminhos:

- **Slow path** (primeiro pacote de uma conexão): o firewall percorre as regras normalmente. Se a decisão for ALLOW, a 5-tupla é registrada na State Table.
- **Fast path** (pacotes subsequentes): o firewall consulta a Hash Table em tempo O(1). Se a 5-tupla já constar como conexão autorizada, o pacote é liberado **instantaneamente**, sem reavaliar nenhuma regra.

### O que ganhamos

| | Stateless | Stateful |
|---|---|---|
| **Performance** | Avalia regras em todo pacote | Avalia regras só no primeiro pacote |
| **Inteligência** | Trata cada pacote isoladamente | Entende o ciclo de vida da conexão |
| **Segurança** | Não detecta pacotes órfãos | Pode bloquear pacotes sem sessão válida |
| **Complexidade** | Simples | Moderada |

A transição de Stateless para Stateful é uma das evoluções mais importantes em segurança de redes — é a base de como firewalls modernos como `iptables`, `pf` e os appliances de enterprise operam.