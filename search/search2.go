package search

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	
	"sync/atomic"
	"time"

	"btchunt/wif"
	"github.com/dustin/go-humanize"
	
)

// Range representa um intervalo de chaves privadas
type Range struct {
	Min           string `json:"min"`
	Max           string `json:"max"`
	Status        string `json:"status"`
	Key           string `json:"key"`
	OriginalStatus string
}

// Ranges contém uma lista de Range
type Ranges struct {
	Ranges []Range
}

// Função para verificar se há 4 ou mais caracteres repetidos consecutivamente (exceto '0')
func hasRepeatedCharacters(key string) bool {
    if len(key) < 7 {
        return false // Se a chave for menor que 4 caracteres, não pode ter repetição
    }

    repeatCount := 1
    for i := 1; i < len(key); i++ {
        if key[i] == key[i-1] && key[i] != '0' {
            repeatCount++
            if repeatCount == 4 {
                //fmt.Printf("Chave pulada devido à repetição: %s\n", key)
                return true // Retorna imediatamente ao encontrar 4 caracteres consecutivos
            }
        } else {
            repeatCount = 1 // Reinicia o contador se os caracteres forem diferentes
        }
    }
    return false
}

// LoadRanges carrega os intervalos do arquivo JSON
func LoadRanges(filename string) (*Ranges, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var ranges Ranges
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&ranges)
    if err != nil {
        return nil, err
    }

    // Processa os endereços
    for i := range ranges.Ranges {
        ranges.Ranges[i].OriginalStatus = ranges.Ranges[i].Status
        
        // Converte o endereço para hash160
        hash160 := wif.AddressToHash160(ranges.Ranges[i].Status)
        ranges.Ranges[i].Status = fmt.Sprintf("%x", hash160)
    }

    return &ranges, nil
}

// GenerateAndSendKeys gera todas as combinações possíveis da chave parcial
func GenerateAndSendKeys(pattern string, keysChan chan<- string, stopSignal chan struct{}) {
    chars := "0123456789abcdef"
    positions := make([]int, 0)
    
    // Encontra as posições dos 'x'
    for i, char := range pattern {
        if char == 'x' {
            positions = append(positions, i)
        }
    }

    // Função recursiva para gerar combinações
    var generateCombinations func(current string, pos int)
    generateCombinations = func(current string, pos int) {
        if pos >= len(positions) {
            // Verifica se a chave tem caracteres repetidos antes de enviá-la
            if !hasRepeatedCharacters(current) {
                select {
                case <-stopSignal:
                    return
                case keysChan <- current:
                }
            }
            return
        }

        position := positions[pos]
        currentBytes := []byte(current)
        
        for _, c := range chars {
            select {
            case <-stopSignal:
                return
            default:
                newBytes := make([]byte, len(currentBytes))
                copy(newBytes, currentBytes)
                newBytes[position] = byte(c)
                generateCombinations(string(newBytes), pos+1)
            }
        }
    }

    // Inicia a geração
    generateCombinations(pattern, 0)
}

// SearchKeys processa as chaves geradas
func SearchKeys(wallets []string, keysChan <-chan string, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64) {
    for keyHex := range keysChan {
        select {
        case <-stopSignal:
            return
        default:
            // Converte a chave hex para big.Int
            privKey := new(big.Int)
            privKey.SetString(keyHex, 16)
            
            // Incrementa o contador
            if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
                printProgress(startTime, keysChecked)
            }

            // Gera a chave pública e endereço
            privKeyBytes := privKey.FillBytes(make([]byte, 32))
            pubKey := wif.GeneratePublicKey(privKeyBytes)
            addressHash160 := wif.Hash160(pubKey)
            addressHash160Hex := fmt.Sprintf("%x", addressHash160)

            // Verifica se encontrou a carteira
            if contains(wallets, addressHash160Hex) {
                wifKey := wif.PrivateKeyToWIF(privKey)
                address := wif.PublicKeyToAddress(pubKey)
                saveFoundKeyDetails(privKey, wifKey, address)
                close(stopSignal)
                return
            }
        }
    }
}

// contains verifica se um endereço está na lista
func contains(wallets []string, addressHash160Hex string) bool {
    for _, wallet := range wallets {
        if wallet == addressHash160Hex {
            return true
        }
    }
    return false
}

// saveFoundKeyDetails salva os detalhes da chave encontrada
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
    fmt.Println("\n-------------------CHAVE ENCONTRADA!!!!-------------------")
    fmt.Printf("Private key: %064x\n", privKey)
    fmt.Printf("WIF: %s\n", wifKey)
    fmt.Printf("Endereço: %s\n", address)

    file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
        return
    }
    defer file.Close()

    _, err = file.WriteString(fmt.Sprintf("\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
    if err != nil {
        fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
    }
}

// printProgress mostra o progresso da busca
func printProgress(startTime time.Time, keysChecked *int64) {
    elapsed := time.Since(startTime)
    keysPerSecond := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
    fmt.Printf("\rKeys Checked: %s  Time: %.2fs  Keys/s: %.2f", 
        humanize.Comma(atomic.LoadInt64(keysChecked)), 
        elapsed.Seconds(), 
        keysPerSecond)
}
