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
	"btchunt/wif" // Importando o pacote wif
        "github.com/fatih/color"
)

// IntervalJumper estrutura para gerenciar o salto entre intervalos
type IntervalJumper struct {
	Ranges       *Ranges
	PrivKeyInt   *big.Int
	MaxPrivKeyInt *big.Int
	Wallets      []string
	StopSignal   chan struct{}
	currentIndex int32
}

// Start inicia o processo de salto entre intervalos
func (ij *IntervalJumper) Start(jumpInterval int) {
	go func() {
		// Cria uma permutação aleatória dos índices dos intervalos
		indices := rand.Perm(len(ij.Ranges.Ranges))
		indexCounter := 0 // Contador para percorrer os índices

		for {
			select {
			case <-ij.StopSignal:
				return
			default:
				// Se todos os índices foram percorridos, reinicia a permutação
				if indexCounter >= len(indices) {
					indices = rand.Perm(len(ij.Ranges.Ranges)) // Gera nova permutação
					indexCounter = 0
				}

				// Obtém o índice atual da permutação
				currentIndex := indices[indexCounter]
				indexCounter++

				// Carrega o intervalo correspondente ao índice atual
				rangeData := ij.Ranges.Ranges[currentIndex]
				ij.PrivKeyInt.SetString(rangeData.Min[2:], 16)
				ij.MaxPrivKeyInt.SetString(rangeData.Max[2:], 16)
				ij.Wallets = strings.Split(rangeData.Status, ", ")

				// Exibe o intervalo atual (opcional para debugging)
				color.Yellow("Saltando para intervalo %d: Min: %s, Max: %s\n", currentIndex, rangeData.Min, rangeData.Max)

				// Aguarda o intervalo de tempo antes de pular para o próximo
				time.Sleep(time.Duration(jumpInterval) * time.Second)
			}
		}
	}()
}

// Range representa um intervalo de chaves privadas
type Range struct {
	Min    string `json:"min"`
	Max    string `json:"max"`
	Status string `json:"status"`
        OriginalStatus string // Adiciona um campo para armazenar os endereços originais
}

// Ranges contém uma lista de Range
type Ranges struct {
	Ranges []Range
}

// LoadRanges carrega os intervalos de chaves privadas a partir de um arquivo JSON e converte os endereços em hash160
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

    // Adiciona um campo para armazenar os endereços originais
    for i := range ranges.Ranges {
        addresses := strings.Split(ranges.Ranges[i].Status, ", ")

        // Cria um campo separado para armazenar os endereços originais
        originalAddresses := make([]string, len(addresses))
        copy(originalAddresses, addresses)

        // Converte endereços para hash160
        var hash160s []string
        for _, address := range addresses {
            hash160 := wif.AddressToHash160(address) // Usando a função do pacote wif
            hash160s = append(hash160s, fmt.Sprintf("%x", hash160))
        }
        ranges.Ranges[i].Status = strings.Join(hash160s, ", ")

        // Armazena os endereços originais em um campo separado
        ranges.Ranges[i].OriginalStatus = strings.Join(originalAddresses, ", ")
    }

    return &ranges, nil
}

// GetRandomBlock gera um bloco de chaves privadas aleatórias dentro do intervalo fornecido
func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64) *big.Int {
	rangeSize := new(big.Int).Sub(maxPrivKey, minPrivKey)
	block := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), rangeSize)

	// Ajusta o bloco para estar dentro do intervalo [minPrivKey, maxPrivKey - blockSize]
	block.Add(block, minPrivKey)
	blockEnd := new(big.Int).Set(block)
	blockEnd.Add(blockEnd, big.NewInt(blockSize))

	if blockEnd.Cmp(maxPrivKey) > 0 {
		// Se o bloco ultrapassar o maxPrivKey, ajusta para estar dentro do intervalo
		block.Sub(maxPrivKey, big.NewInt(blockSize))
	}

	return block
}

// SearchInBlockBatch busca chaves privadas em lotes dentro de um bloco
func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
	for block := range taskChan {
		privKey := new(big.Int)
		var privKeyBatch []*big.Int
		for i := int64(0); i < blockSize; i++ {
			privKey.Add(block, big.NewInt(i))
			privKeyBatch = append(privKeyBatch, new(big.Int).Set(privKey))

			// Processa o lote ao atingir o tamanho do batch
			if len(privKeyBatch) == batchSize {
				verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
				privKeyBatch = privKeyBatch[:0] // Limpa o batch
			}
		}
		// Processa o restante do lote
		if len(privKeyBatch) > 0 {
			verifyBatch(privKeyBatch, wallets, stopSignal, keysChecked, checkInterval, startTime)
		}
	}
}

// Função para verificar se há 4 ou mais caracteres repetidos consecutivamente (exceto '0')
func hasRepeatedCharacters(key string) bool {
    if len(key) < 4 {
        return false // Se a chave for menor que 4 caracteres, não pode ter repetição
    }

    repeatCount := 1
    for i := 1; i < len(key); i++ {
        if key[i] == key[i-1] && key[i] != '0' {
            repeatCount++
            if repeatCount == 4 {
               // fmt.Printf("Chave pulada devido à repetição: %s\n", key)
                return true // Retorna imediatamente ao encontrar 4 caracteres consecutivos
            }
        } else {
            repeatCount = 1 // Reinicia o contador se os caracteres forem diferentes
        }
    }
    return false
}

// verifyBatch verifica um lote de chaves de uma só vez
func verifyBatch(privKeyBatch []*big.Int, wallets []string, stopSignal chan struct{}, keysChecked *int64, checkInterval int64, startTime time.Time) {
	pubKeys := make([][]byte, len(privKeyBatch))
	var closed int32 // Variável atômica para rastrear o estado do canal

	for i, privKey := range privKeyBatch {
		privKeyBytes := privKey.FillBytes(make([]byte, 32))

		// Incrementa o contador de chaves verificadas
		if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
			printProgress(startTime, keysChecked)
		}
		
		// Converte a chave para string hexadecimal e verifica se contém caracteres repetidos
		privKeyHex := fmt.Sprintf("%064x", privKey) // Converte para hexadecimal
		if hasRepeatedCharacters(privKeyHex) {
			continue // Ignora se houver 4 ou mais caracteres repetidos
		}

		// Se não houver repetição de caracteres, gera a chave pública
		pubKeys[i] = wif.GeneratePublicKey(privKeyBytes) // Usando função do pacote wif
	}

	for i, pubKey := range pubKeys {
		// Se a chave pública for nula (foi ignorada devido à repetição de caracteres), continue
		if pubKey == nil {
			continue
		}

		addressHash160 := wif.Hash160(pubKey) // Usando função do pacote wif
		addressHash160Hex := fmt.Sprintf("%x", addressHash160)

		if contains(wallets, addressHash160Hex) {
			privKey := privKeyBatch[i]
			wifKey := wif.PrivateKeyToWIF(privKey) // Usando função do pacote wif
			address := wif.PublicKeyToAddress(pubKey) // Usando função do pacote wif
			saveFoundKeyDetails(privKey, wifKey, address)

			// Fecha o stopSignal apenas se ainda não tiver sido fechado
			if atomic.CompareAndSwapInt32(&closed, 0, 1) {
				close(stopSignal)
			}
			return
		}
	}
}
// contains verifica se um endereço hash está na lista de wallets
func contains(wallets []string, addressHash160Hex string) bool {
	for _, wallet := range wallets {
		if wallet == addressHash160Hex {
			return true
		}
	}
	return false
}

// saveFoundKeyDetails salva os detalhes da chave privada encontrada em um arquivo
func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
	fmt.Println("-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("Private key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
	if err != nil {
		fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
	}
}


// printProgress imprime o progresso da busca
func printProgress(startTime time.Time, keysChecked *int64) {
	elapsed := time.Since(startTime)
	chavesPorSegundo := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("Keys Checked: %s  Time: %.8ss  Keys/s: %.2f\n", 
		humanize.Comma(atomic.LoadInt64(keysChecked)), 
		elapsed, 
		chavesPorSegundo)
}
