package main

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"btchunt/search" // Certifique-se que este import está correto para o seu projeto

	"github.com/fatih/color"
)

const (
	checkInterval  = 500000       // Checagem a cada 500k de chaves
	jumpInterval   = 60           // Tempo em segundos para verificar um intervalo
	numGoroutines  = 8            // Threads da CPU
	blockSize      = int64(10000) // Tamanho dos blocos
	batchSize      = 100000       // Tamanho do lote para verificação
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
	// Carrega os ranges do arquivo
	ranges, err := search.LoadRanges("ranges.json")
	if err != nil {
		log.Fatalf("Failed to load ranges: %v", err)
	}

	// Arte ASCII
	color.Cyan(`
██████╗ ████████╗ ██████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔══██╗╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██████╔╝   ██║   ██║     ███████║██║   ██║██╔██╗ ██║   ██║   
██╔══██╗   ██║   ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   
██████╔╝   ██║   ╚██████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
v1.8 - Deadlock Fixed
`)

	var rangeNumber int
	if len(ranges.Ranges) == 1 {
		fmt.Println("Wallets a serem buscadas:")
		color.Green(ranges.Ranges[rangeNumber].OriginalStatus)
		color.Yellow("Apenas um intervalo detectado. Desabilitando jumpInterval.")
		rangeNumber = 0
	} else {
		fmt.Println("Wallets a serem buscadas:")
		color.Green(ranges.Ranges[rangeNumber].OriginalStatus)
		color.Green("Múltiplos intervalos detectados. jumpInterval ativado.")
		rangeNumber = getRandomRange(len(ranges.Ranges))
	}

	privKeyHex := ranges.Ranges[rangeNumber].Min
	maxPrivKeyHex := ranges.Ranges[rangeNumber].Max
	wallets := strings.Split(ranges.Ranges[rangeNumber].Status, ", ")

	privKeyInt := new(big.Int)
	privKeyInt.SetString(privKeyHex[2:], 16)
	maxPrivKeyInt := new(big.Int)
	maxPrivKeyInt.SetString(maxPrivKeyHex[2:], 16)

	startTime := time.Now()
	stopSignal := make(chan struct{}) // Canal para sinalizar parada
	var wg sync.WaitGroup
	var keysChecked int64

	// Inicializa o gerenciador de saltos entre intervalos
	intervalJumper := &search.IntervalJumper{
		Ranges:        ranges,
		PrivKeyInt:    privKeyInt,
		MaxPrivKeyInt: maxPrivKeyInt,
		Wallets:       wallets,
		StopSignal:    stopSignal,
	}

	// Canal de tarefas com buffer
	taskChan := make(chan *big.Int, numGoroutines*2)

	// Inicia os Workers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			search.SearchInBlockBatch(wallets, blockSize, privKeyInt, maxPrivKeyInt, stopSignal, startTime, id, &keysChecked, checkInterval, taskChan, batchSize)
		}(i)
	}

	// Inicia o Jumper se necessário
	if len(ranges.Ranges) > 1 {
		go func() {
			intervalJumper.Start(jumpInterval)
		}()
	}

	// --- LOOP PRINCIPAL CORRIGIDO ---
	// Distribui blocos até que o sinal de parada seja acionado
	for {
		// 1. Gera o bloco
		block := search.GetRandomBlock(privKeyInt, maxPrivKeyInt, blockSize, false)

		// 2. Tenta enviar o bloco OU sair se o stopSignal for fechado
		select {
		case taskChan <- block:
			// Bloco enviado com sucesso, continua o loop
		case <-stopSignal:
			// Sinal de parada recebido (chave encontrada), encerra tudo
			close(taskChan) // Fecha o canal para garantir que workers restantes saiam
			wg.Wait()       // Espera todos os workers terminarem
			return          // Encerra o programa
		}
	}
}

func getRandomRange(numRanges int) int {
	return rng.Intn(numRanges)
}
