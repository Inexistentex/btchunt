
package main

import (
        "fmt"
        "log"
        "sync"

        "btchunt/search"
)

const (
        threadCount = 4   // N  mero de threads
        blockSize   = 1000000 // N  mero m  ximo de tentativas por bloco
)

func main() {
        // Inicializa o controle de concorr  ncia
        var wg sync.WaitGroup
        wg.Add(threadCount)

        // Cria canais de controle para comunica    o
        foundChan := make(chan bool, 1)
        defer close(foundChan)

        // Inicia as threads
        for i := 0; i < threadCount; i++ {
                go func(threadID int) {
                        defer wg.Done()
                        search.StartSearch(threadID, blockSize, foundChan)
                }(i)
        }

        // Aguarda at   que todas as threads concluam
        wg.Wait()
        fmt.Println("Busca conclu  da.")
}
