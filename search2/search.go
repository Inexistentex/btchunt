package search

import (
    "encoding/json"
    "fmt"
    "math/big"
    "os"
    "strings"
    "sync/atomic"
    "time"
    "math/rand"
    "github.com/dustin/go-humanize"
    "btchunt/wif"
)

// Range representa um intervalo de chaves privadas
type Range struct {
    Min            string `json:"min"`
    Max            string `json:"max"`
    Status         string `json:"status"`
    Key            string `json:"key"`
    OriginalStatus string
}

// Ranges contém uma lista de Range
type Ranges struct {
    Ranges []Range
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
        hash160 := wif.AddressToHash160(ranges.Ranges[i].Status)
        ranges.Ranges[i].Status = fmt.Sprintf("%x", hash160)
    }

    return &ranges, nil
}

// Função para verificar se há 4 ou mais caracteres repetidos consecutivamente 
func hasRepeatedCharacters(key string) bool {
    if len(key) < 7 {
        return false
    }

    repeatCount := 1
    for i := 1; i < len(key); i++ {
          if key[i] == key[i-1] {
            repeatCount++
            if repeatCount == 4 {
                return true
            }
        } else {
            repeatCount = 1
        }
    }
    return false
}

func getRandomBlock(pattern string, rng *rand.Rand) string {
    chars := "0123456789abcdef"
    result := make([]byte, len(pattern))

    for i, char := range pattern {
        if char == 'x' {
            randIndex := int(rng.Int63() % int64(len(chars))) // Usa o gerador Xoshiro
            result[i] = chars[randIndex]
        } else {
            result[i] = byte(char)
        }
    }
    return string(result)
}

func GenerateAndSendKeys(pattern string, keysChan chan<- string, stopSignal chan struct{}, blockSize int64) {
    chars := "0123456789abcdef"
    blockCount := 0

    // Criação do gerador de números aleatórios
    rng := rand.New(rand.NewSource(time.Now().UnixNano()))

    for {
        // Chamada corrigida para incluir o gerador rng
        baseKey := getRandomBlock(pattern, rng)
        blockCount++

        var attempts int64 = 0
        currentKey := []byte(baseKey)
        firstKeyInBlock := string(currentKey)
        var lastKeyInBlock string

        for attempts < blockSize {
            select {
            case <-stopSignal:
                return
            default:
                if !hasRepeatedCharacters(string(currentKey)) {
                    keysChan <- string(currentKey)
                    attempts++
                    lastKeyInBlock = string(currentKey)
                }

                incrementou := false
                for i := len(currentKey) - 1; i >= 0; i-- {
                    if pattern[i] == 'x' {
                        currentIndex := strings.IndexByte(chars, currentKey[i])
                        if currentIndex < len(chars)-1 {
                            currentKey[i] = chars[currentIndex+1]
                            incrementou = true
                            break
                        } else {
                            currentKey[i] = '0'
                        }
                    }
                }

                if !incrementou {
                    break
                }
            }
        }

        select {
        case <-stopSignal:
            return
        default:
            fmt.Printf("\nBloco #%d - Primeira: %s Última: %s",
                blockCount, firstKeyInBlock, lastKeyInBlock)
            continue
        }
    }
}

// SearchInBlockBatch processa as chaves em lotes
func SearchInBlockBatch(wallets []string, keysChan <-chan string, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, batchSize int) {
    var keyBatch []string

    for keyHex := range keysChan {
        select {
        case <-stopSignal:
            return
        default:
            keyBatch = append(keyBatch, keyHex)

            if len(keyBatch) == batchSize {
                processBatch(keyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
                keyBatch = keyBatch[:0]
            }
        }
    }

    if len(keyBatch) > 0 {
        processBatch(keyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
    }
}

// processBatch processa um lote de chaves
func processBatch(keyBatch []string, wallets []string, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time) {
    for _, keyHex := range keyBatch {
        select {
        case <-stopSignal:
            return
        default:
            privKey := new(big.Int)
            privKey.SetString(keyHex, 16)

            if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
                printProgress(startTime, keysChecked)
            }

            privKeyBytes := privKey.FillBytes(make([]byte, 32))
            pubKey := wif.GeneratePublicKey(privKeyBytes)
            addressHash160 := wif.Hash160(pubKey)
            addressHash160Hex := fmt.Sprintf("%x", addressHash160)

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

// SaveProgress salva o progresso atual em um arquivo
func SaveProgress(keysChecked int64, lastKey string) error {
    progress := struct {
        KeysChecked int64  `json:"keys_checked"`
        LastKey     string `json:"last_key"`
        Timestamp   string `json:"timestamp"`
    }{
        KeysChecked: keysChecked,
        LastKey:     lastKey,
        Timestamp:   time.Now().Format(time.RFC3339),
    }

    file, err := os.Create("progress.json")
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    return encoder.Encode(progress)
}

// LoadProgress carrega o progresso salvo de um arquivo
func LoadProgress() (int64, string, error) {
    file, err := os.Open("progress.json")
    if err != nil {
        if os.IsNotExist(err) {
            return 0, "", nil
        }
        return 0, "", err
    }
    defer file.Close()

    var progress struct {
        KeysChecked int64  `json:"keys_checked"`
        LastKey     string `json:"last_key"`
        Timestamp   string `json:"timestamp"`
    }

    decoder := json.NewDecoder(file)
    err = decoder.Decode(&progress)
    if err != nil {
        return 0, "", err
    }

    return progress.KeysChecked, progress.LastKey, nil
}
