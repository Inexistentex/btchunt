package main

import (
    "fmt"
    "log"
    "strings"
    "sync"
    "time"

    "btchunt/search2" // Corrigido para usar 'search'
    "github.com/fatih/color"
)

const (
    checkInterval = 500000         // Checagem a cada 200k de chaves
    numGoroutines = 4              // Threads da CPU                                                                     
    blockSize     = int64(10000)  // Tamanho do bloco de tentativas
    batchSize     = 100000         // Tamanho do lote para processamento em batch
)

func main() {
    // Carrega os ranges do arquivo
    ranges, err := search.LoadRanges("ranges2.json")
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

    // Exibe informações iniciais
    fmt.Println("Wallet a ser buscada:")
    color.Green(ranges.Ranges[0].OriginalStatus)
    fmt.Println("Padrão da chave:")
    color.Yellow(ranges.Ranges[0].Key)

    pattern := ranges.Ranges[0].Key
    wallets := strings.Split(ranges.Ranges[0].Status, ", ")

    startTime := time.Now()
    stopSignal := make(chan struct{})
    var wg sync.WaitGroup
    var keysChecked int64

    // Cria um canal para distribuir as chaves geradas
    keysChan := make(chan string, numGoroutines)

    // Inicia as goroutines para busca
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            search.SearchInBlockBatch(wallets, keysChan, stopSignal, startTime, id, &keysChecked, checkInterval, batchSize)
        }(i)
    }

    // Gera e envia as chaves para o canal
    go func() {
        search.GenerateAndSendKeys(pattern, keysChan, stopSignal, blockSize, numGoroutines)
        close(keysChan)
    }()

    // Aguarda todas as goroutines terminarem
    wg.Wait()
}
