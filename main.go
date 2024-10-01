package main

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"btchunt/search"
	"github.com/fatih/color"
)

const (
	checkInterval  = 200000 // Checagem a cada 200k de chaves
	jumpInterval   = 60 // Tempo em segundos para ver0ificar um intervalo
	numGoroutines  = 4 // Threads da CPU
	blockSize      = int64(1000) // Tamanho dos blocos
	batchSize      = 10000 // Tamanho do lote para verificação
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
    // Declaração da variável ranges e err
    ranges, err := search.LoadRanges("ranges.json")
    if err != nil {
        log.Fatalf("Failed to load ranges: %v", err)
    }

    // Usando uma raw string para a arte ASCII
    color.Cyan(`
██████╗ ████████╗ ██████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔══██╗╚══██╔══╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██████╔╝   ██║   ██║     ███████║██║   ██║██╔██╗ ██║   ██║   
██╔══██╗   ██║   ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   
██████╔╝   ██║   ╚██████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
`)

    var rangeNumber int
    if len(ranges.Ranges) == 1 {
        // Exibe os endereços originais
        fmt.Println("Wallets a serem buscadas:")
        color.Green(ranges.Ranges[rangeNumber].OriginalStatus)

        color.Yellow("Apenas um intervalo detectado. Desabilitando jumpInterval.")
        rangeNumber = 0 // Define como o único intervalo disponível
    } else {
        // Exibe os endereços originais
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
	stopSignal := make(chan struct{})
	var wg sync.WaitGroup
	var keysChecked int64

	intervalJumper := &search.IntervalJumper{
		Ranges:        ranges,
		PrivKeyInt:    privKeyInt,
		MaxPrivKeyInt: maxPrivKeyInt,
		Wallets:       wallets,
		StopSignal:    stopSignal,
	}

	taskChan := make(chan *big.Int, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			search.SearchInBlockBatch(wallets, blockSize, privKeyInt, maxPrivKeyInt, stopSignal, startTime, id, &keysChecked, checkInterval, taskChan, batchSize)
		}(i)
	}

	if len(ranges.Ranges) > 1 { // Ativa o jumpInterval apenas se houver mais de um intervalo
		go func() {
			intervalJumper.Start(jumpInterval)
		}()
	}

	// Distribui blocos para processamento
	for {
		select {
		case <-stopSignal:
			close(taskChan)
			wg.Wait()
			return
		default:
			block := search.GetRandomBlock(privKeyInt, maxPrivKeyInt, blockSize)
			taskChan <- block
		}
	}
}

func getRandomRange(numRanges int) int {
	return rng.Intn(numRanges)
}
