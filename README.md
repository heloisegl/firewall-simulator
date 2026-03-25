# Simulador de Firewall
Este projeto é um simulador simples de firewall por regras. Ele lê regras e pacotes em JSON, valida esses dados, transforma tudo em objetos python tipados e decide se cada pacote deve ser ALLOW ou BLOCK com base na primeira regra compatível.

### Estrutura do projeto
```bash
firewall_simulator/
│
├── app/
│   ├── main.py
│   │
│   ├── models/
│   │   ├── packet.py
│   │   ├── rule.py
│   │   ├── enums.py
│   │   └── decision.py
│   │
│   ├── engine/
│   │   ├── firewall.py
│   │   └── policy.py
│   │
│   ├── parser/
│   │   ├── rules_parser.py
│   │   ├── packets_parser.py
│   │   └── validators.py
│   │
│   ├── logging_system/ # A ADICIONAR!
│   │   └── logger.py
│   │
│   ├── stats/ # A ADICIONAR!
│   │   └── statistics.py
│   │
│   └── simulation/ # A ADICIONAR!
│       └── packet_generator.py
│
├── data/
│   ├── rules.json
│   ├── packets.json
│   └── logs/
│
│── .gitignore
└── README.md
```