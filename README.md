# BTCHunt - High Performance CPU Bitcoin Puzzle Solver

BTCHunt é uma ferramenta de força bruta de alto desempenho projetada para resolver os Bitcoin Puzzles (intervalos de chaves privadas conhecidos).

Este projeto foca na velocidade máxima de CPU, utilizando otimizações de baixo nível (Assembly), alocação de memória zero em loops críticos e uma arquitetura de workers totalmente autônomos.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-gray)
![Performance](https://img.shields.io/badge/Performance-High-brightgreen)

Funcionalidades (v4.0)

Arquitetura de Workers Autônomos: Remove o gargalo de comunicação entre threads. Cada núcleo do processador trabalha de forma independente, garantindo **100% de uso de CPU**.
* Native Go Assembly: Utiliza a biblioteca `decred/secp256k1`, que roda em Assembly otimizado diretamente no Go, eliminando o atraso (overhead) de chamadas CGO.
* Estratégia Híbrida Inteligente: Combina saltos aleatórios (para cobrir grandes áreas) com varredura sequencial ultrarrápida (usando adição de pontos na curva elíptica).
* Zero Allocation: O código crítico de hashing (SHA256 + RIPEMD160) e serialização não gera lixo na memória (GC), evitando pausas no processamento.
* Multi-Platform: Compila nativamente para Linux e Windows.

---

  Pré-requisitos

Go 1.22 ou superior instalado.

---

  Instalação e Compilação

 1. Clonar ou Baixar o Projeto
Certifique-se de que os arquivos `main.go`, `ranges.json` e a pasta `search/` estão organizados.
