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

// Estrutura global para o gerador xoshiro256
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

// IntervalJumper estrutura para gerenciar o salto entre intervalos
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

// SearchInBlockBatch otimizada com Point Addition e Zero-Allocation Hashing
func SearchInBlockBatch(wallets []string, blockSize int64, minPrivKey, maxPrivKey *big.Int, stopSignal chan struct{}, startTime time.Time, id int, keysChecked *int64, checkInterval int64, taskChan chan *big.Int, batchSize int) {
	fullyRandom := id%2 == 0
	xoshiro := NewXoshiro256()

	// 1. Preparar mapa de alvos (Bytes diretos)
	targetMap := make(map[[20]byte]struct{})
	for _, w := range wallets {
		bytes, err := hex.DecodeString(w)
		if err == nil && len(bytes) == 20 {
			var arr [20]byte
			copy(arr[:], bytes)
			targetMap[arr] = struct{}{}
		}
	}

	// 2. Preparar estruturas criptográficas reutilizáveis
	curve := secp256k1.S256()
	Gx, Gy := curve.Gx, curve.Gy // Ponto gerador

	// Buffers para evitar alocação de memória no loop
	sha := sha256.New()
	ripe := ripemd160.New()
	pubKeyCompressed := make([]byte, 33)
	shaBuf := make([]byte, 32)
	ripeBuf := make([]byte, 20)
	var hashArr [20]byte // Chave para o mapa

	// Variáveis big.Int reutilizáveis
	rndVal := new(big.Int)
	diff := new(big.Int).Sub(maxPrivKey, minPrivKey)
	currentPrivKey := new(big.Int)

	for block := range taskChan {
		if fullyRandom {
			// --- MODO TOTALMENTE ALEATÓRIO ---
			randomBits := make([]byte, 32)
			for i := int64(0); i < blockSize; i++ {
				// Gera chave aleatória
				binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
				binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
				binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
				binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

				rndVal.SetBytes(randomBits)
				rndVal.Mod(rndVal, diff)
				rndVal.Add(rndVal, minPrivKey)

				// Calcula PubKey (Lento, mas necessário para aleatório)
				// Nota: Para aleatório puro não podemos usar point addition facilmente
				x, y := curve.ScalarBaseMult(rndVal.Bytes())
				
				// Serializa manualmente (Zero Allocation)
				serializeCompressed(x, y, pubKeyCompressed)

				// Hash inline (Zero Allocation)
				sha.Reset()
				sha.Write(pubKeyCompressed)
				sha.Sum(shaBuf[:0]) // Escreve no buffer existente

				ripe.Reset()
				ripe.Write(shaBuf)
				ripe.Sum(ripeBuf[:0])

				// Verifica
				copy(hashArr[:], ripeBuf)
				if _, found := targetMap[hashArr]; found {
					foundKey(rndVal, pubKeyCompressed, "fullyRandom", stopSignal)
					return
				}

				if atomic.AddInt64(keysChecked, 1)%checkInterval == 0 {
					printProgress(startTime, keysChecked)
				}
			}

		} else {
			// --- MODO SEQUENCIAL (SUPER OTIMIZADO) ---
			
			// Calcula o ponto inicial com multiplicação normal
			currentPrivKey.Set(block)
			x, y := curve.ScalarBaseMult(currentPrivKey.Bytes())

			for i := int64(0); i < blockSize; i++ {
				// 1. Serializa (Manualmente)
				serializeCompressed(x, y, pubKeyCompressed)

				// 2. Hash Inline (SHA256 + RIPEMD160)
				sha.Reset()
				sha.Write(pubKeyCompressed)
				sha.Sum(shaBuf[:0])

				ripe.Reset()
				ripe.Write(shaBuf)
				ripe.Sum(ripeBuf[:0])

				// 3. Verifica no Mapa
				copy(hashArr[:], ripeBuf)
				if _, found := targetMap[hashArr]; found {
					// Recalcula a chave privada exata: block + i
					privKeyFound := new(big.Int).Add(block, big.NewInt(i))
					foundKey(privKeyFound, pubKeyCompressed, "sequential", stopSignal)
					return
				}

				// 4. PREPARA A PRÓXIMA CHAVE: Point Addition (Muito Rápido)
				// Em vez de multiplicar (k+1)*G, fazemos PontoAtual + G
				x, y = curve.Add(x, y, Gx, Gy)
				
				// Verifica fim do bloco/sinal (Otimização: checagem leve)
				if i%1000 == 0 {
					select {
					case <-stopSignal:
						return
					default:
					}
					if atomic.AddInt64(keysChecked, 1000)%checkInterval == 0 {
						printProgress(startTime, keysChecked)
					}
				}
			}
		}
	}
}

// serializeCompressed serializa x,y para formato comprimido sem alocar memória
func serializeCompressed(x, y *big.Int, buf []byte) {
	buf[0] = 0x02 // Assumimos par
	if y.Bit(0) == 1 {
		buf[0] = 0x03 // Ímpar
	}
	// Preenche os 32 bytes de X
	xBytes := x.Bytes()
	copy(buf[1+(32-len(xBytes)):], xBytes)
	// Limpa bytes anteriores se X for pequeno (raro, mas seguro)
	for i := 1; i < 1+(32-len(xBytes)); i++ {
		buf[i] = 0
	}
}

func foundKey(privKey *big.Int, pubKeyBytes []byte, mode string, stopSignal chan struct{}) {
	wifKey := wif.PrivateKeyToWIF(privKey)
	address := wif.PublicKeyToAddress(pubKeyBytes)
	saveFoundKeyDetails(privKey, wifKey, address, mode)
	
	// Tenta fechar o canal de forma segura
	select {
	case <-stopSignal:
	default:
		close(stopSignal)
	}
}

func GetRandomBlock(minPrivKey, maxPrivKey *big.Int, blockSize int64, fullyRandom bool) *big.Int {
	xoshiro := NewXoshiro256()

	if fullyRandom {
		// No modo random, o bloco é apenas um placeholder para o range
		// Retornamos um ponto aleatório qualquer dentro do range
		diff := new(big.Int).Sub(maxPrivKey, minPrivKey)
		randomBits := make([]byte, 32)
		binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
		binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

		randomInt := new(big.Int).SetBytes(randomBits)
		randomInt.Mod(randomInt, diff)
		return randomInt.Add(randomInt, minPrivKey)
	}

	rangeSize := new(big.Int).Sub(maxPrivKey, minPrivKey)
	randomBits := make([]byte, 32)
	binary.BigEndian.PutUint64(randomBits[0:8], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[8:16], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[16:24], xoshiro.Next())
	binary.BigEndian.PutUint64(randomBits[24:32], xoshiro.Next())

	block := new(big.Int).SetBytes(randomBits)
	block.Mod(block, rangeSize)
	block.Add(block, minPrivKey)

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
	chavesPorSegundo := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rKeys Checked: %s  Time: %.0fs  Keys/s: %s",
		humanize.Comma(atomic.LoadInt64(keysChecked)),
		elapsed.Seconds(),
		humanize.Comma(int64(chavesPorSegundo)))
}
