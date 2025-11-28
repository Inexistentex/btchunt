package search

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"btchunt/wif"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"golang.org/x/crypto/ripemd160"
)

// --- PRNG Xoshiro256 (Ultra Rápido) ---
type Xoshiro256 struct {
	state [4]uint64
}

func NewXoshiro256() *Xoshiro256 {
	x := &Xoshiro256{}
	seed := make([]byte, 32)
	rand.Read(seed)
	x.state[0] = binary.BigEndian.Uint64(seed[0:8])
	x.state[1] = binary.BigEndian.Uint64(seed[8:16])
	x.state[2] = binary.BigEndian.Uint64(seed[16:24])
	x.state[3] = binary.BigEndian.Uint64(seed[24:32])
	return x
}

func (x *Xoshiro256) Next() uint64 {
	result := rotl(x.state[1]*5, 7) * 9
	t := x.state[1] << 17
	x.state[2] ^= x.state[0]
	x.state[3] ^= x.state[1]
	x.state[1] ^= x.state[2]
	x.state[0] ^= x.state[3]
	x.state[2] ^= t
	x.state[3] = rotl(x.state[3], 45)
	return result
}

func rotl(x uint64, k int) uint64 {
	return (x << k) | (x >> (64 - k))
}

// --- Estruturas Auxiliares ---
type IntervalJumper struct {
	Ranges        *Ranges
	PrivKeyInt    *big.Int
	MaxPrivKeyInt *big.Int
	Wallets       []string
	StopSignal    chan struct{}
}

func (ij *IntervalJumper) Start(jumpInterval int) {
	go func() {
		indices := rand.Perm(len(ij.Ranges.Ranges))
		indexCounter := 0
		for {
			if indexCounter >= len(indices) {
				indices = rand.Perm(len(ij.Ranges.Ranges))
				indexCounter = 0
			}
			currentIndex := indices[indexCounter]
			indexCounter++
			rangeData := ij.Ranges.Ranges[currentIndex]
			ij.PrivKeyInt.SetString(rangeData.Min[2:], 16)
			ij.MaxPrivKeyInt.SetString(rangeData.Max[2:], 16)
			ij.Wallets = strings.Split(rangeData.Status, ", ")
			color.Yellow("Saltando para intervalo %d: Min: %s, Max: %s\n", currentIndex, rangeData.Min, rangeData.Max)
			time.Sleep(time.Duration(jumpInterval) * time.Second)
		}
	}()
}

type Range struct {
	Min            string `json:"min"`
	Max            string `json:"max"`
	Status         string `json:"status"`
	OriginalStatus string
}

type Ranges struct {
	Ranges []Range
}

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
	for i := range ranges.Ranges {
		addresses := strings.Split(ranges.Ranges[i].Status, ", ")
		originalAddresses := make([]string, len(addresses))
		copy(originalAddresses, addresses)
		var hash160s []string
		for _, address := range addresses {
			hash160 := wif.AddressToHash160(address)
			hash160s = append(hash160s, fmt.Sprintf("%x", hash160))
		}
		ranges.Ranges[i].Status = strings.Join(hash160s, ", ")
		ranges.Ranges[i].OriginalStatus = strings.Join(originalAddresses, ", ")
	}
	return &ranges, nil
}

// --- CORE DE BUSCA OTIMIZADO (SEM MODO LENTO) ---

func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
	// OTIMIZAÇÃO: Ignoramos o 'id'. Todos os workers agora usam o modo rápido (Sequencial).
	
	// 1. Mapa de Alvos O(1) com Array de Bytes
	targetMap := make(map[[20]byte]struct{})
	for _, w := range wallets {
		bytes, err := hex.DecodeString(w)
		if err == nil && len(bytes) == 20 {
			var arr [20]byte
			copy(arr[:], bytes)
			targetMap[arr] = struct{}{}
		}
	}

	// 2. Prepara Curva e Buffers Reutilizáveis
	curve := secp256k1.S256()
	Gx, Gy := curve.Gx, curve.Gy // Cache dos pontos geradores

	// Buffers estáticos para evitar alocação de memória (Zero Allocation)
	sha := sha256.New()
	ripe := ripemd160.New()
	pubKeyCompressed := make([]byte, 33)
	shaBuf := make([]byte, 32)
	ripeBuf := make([]byte, 20)
	var hashArr [20]byte

	// Contador local para reduzir contenção atômica
	var localKeysChecked int64 = 0
	// Aumentamos a frequência de atualização local para reduzir overhead de lock da CPU
	const updateFrequency = 10000 

	for block := range taskChan {
		// OTIMIZAÇÃO MÁXIMA: 
		// O 'block' recebido já é um ponto de partida aleatório (gerado pelo main.go).
		// Não precisamos gerar outro aleatório aqui.
		// Apenas calculamos o ponto inicial e corremos sequencialmente (Point Addition).
		
		// 1. Ponto Inicial (Lento, mas feito apenas 1 vez por bloco)
		x, y := curve.ScalarBaseMult(block.Bytes())

		// 2. Loop Rápido (Point Addition)
		for i := int64(0); i < blockSize; i++ {
			// A. Serializa (Manual e Rápido)
			// Byte 0: Prefixo (0x02 par, 0x03 ímpar)
			pubKeyCompressed[0] = 0x02 | byte(y.Bit(0))
			// Bytes 1-32: Coordenada X
			x.FillBytes(pubKeyCompressed[1:])

			// B. Hash SHA256 (Reset/Write/Sum sem alocação)
			sha.Reset()
			sha.Write(pubKeyCompressed)
			sha.Sum(shaBuf[:0])

			// C. Hash RIPEMD160
			ripe.Reset()
			ripe.Write(shaBuf)
			ripe.Sum(ripeBuf[:0])

			// D. Verifica Map (Comparação de bytes diretos)
			copy(hashArr[:], ripeBuf)
			if _, found := targetMap[hashArr]; found {
				// SUCESSO! Recalcula a chave privada exata
				privKeyFound := new(big.Int).Add(block, big.NewInt(i))
				foundKey(privKeyFound, pubKeyCompressed, "fast-sequential", stopSignal)
				return
			}

			// E. Próximo Ponto: Soma P + G (Muito mais rápido que multiplicar)
			x, y = curve.Add(x, y, Gx, Gy)

			// F. Atualização de Progresso (em lotes grandes)
			localKeysChecked++
			if localKeysChecked >= updateFrequency {
				// Atualiza contador global
				if atomic.AddInt64(keysChecked, localKeysChecked)%checkInterval == 0 {
					printProgress(startTime, keysChecked)
				}
				localKeysChecked = 0
				
				// Verifica sinal de parada (sem bloquear)
				select {
				case <-stopSignal:
					return
				default:
				}
			}
		}
		
		// Atualiza qualquer resto do contador ao fim do bloco
		if localKeysChecked > 0 {
			atomic.AddInt64(keysChecked, localKeysChecked)
			localKeysChecked = 0
		}
	}
}

func foundKey(privKey *big.Int, pubKeyBytes []byte, mode string, stopSignal chan struct{}) {
	wifKey := wif.PrivateKeyToWIF(privKey)
	address := wif.PublicKeyToAddress(pubKeyBytes)
	
	// Tenta fechar o sinal de forma segura (idempotente)
	select {
	case <-stopSignal:
		return
	default:
		close(stopSignal)
		saveFoundKeyDetails(privKey, wifKey, address, mode)
	}
}

func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64, fullyRandom bool) *big.Int {
	xoshiro := NewXoshiro256()

	// Nota: Removemos a lógica antiga de fullyRandom aqui pois o main controla.
	// O main sempre chama com false, então geramos um ponto de partida aleatório.
	rangeSize := new(big.Int).Sub(maxPrivKey, minPrivKey)
	randomBits := make([]byte, 32)
	binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

	block := new(big.Int).SetBytes(randomBits)
	block.Mod(block, rangeSize)
	block.Add(block, minPrivKey)

	// Ajusta para não estourar o Max
	blockEnd := new(big.Int).Set(block)
	blockEnd.Add(blockEnd, big.NewInt(blockSize))

	if blockEnd.Cmp(maxPrivKey) > 0 {
		block.Sub(maxPrivKey, big.NewInt(blockSize))
	}

	return block
}

func saveFoundKeyDetails(privKey *big.Int, wifKey, address string, mode string) {
	fmt.Println(" ")
	fmt.Println("-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Modo de Busca: %s\n", mode)
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, _ := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()
	file.WriteString(fmt.Sprintf("Modo de Busca: %s\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", mode, privKey, wifKey, address))
}

func printProgress(startTime time.Time, keysChecked *int64) {
	elapsed := time.Since(startTime)
	if elapsed.Seconds() == 0 { return }
	chavesPorSegundo := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rKeys Checked: %s  Time: %.0fs  Keys/s: %s",
		humanize.Comma(atomic.LoadInt64(keysChecked)),
		elapsed.Seconds(),
		humanize.Comma(int64(chavesPorSegundo)))
}
