package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

var (
	beginTime      time.Time
	s256           *btcec.KoblitzCurve
	net            *chaincfg.Params
	numFound       uint64
	numGenerated   uint64
	np             int
	threadsPerCore int
	prefixFlag     string
	patternFlag    string
	outmu          sync.Mutex
)

type MatchFunc func(s string) bool

type VanityAddr struct {
	pubkey  [65]byte
	privkey *btcec.PrivateKey
	wif     *btcutil.WIF
	addr    string
	seed    []byte
}

func setupSignals(stopc chan<- struct{}) {
	ctrlc := make(chan os.Signal, 2)

	signal.Notify(ctrlc, os.Interrupt, syscall.SIGTERM)
	go func(stopc chan<- struct{}) {
		<-ctrlc
		stopc <- struct{}{}
	}(stopc)
}

func getMatchFunc(prefix string, pattern string) (MatchFunc, error) {
	if len(pattern) > 0 {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("must supply valid regexp: %v\n", err))
		}
		return MatchFunc(func(s string) bool { return re.MatchString(s) }), nil
	}

	if len(prefix) > 0 {
		if len(prefix) < 1 || len(prefix) > 34 {
			return nil, errors.New(fmt.Sprintf("prefix %s has invalid length %d", prefix, len(prefix)))
		} else if strings.ContainsAny(prefix, "0IOl`~-_=+[{]}\\|;:'\",<.>/?!@#$%^&*()") {
			return nil, errors.New(fmt.Sprintf("prefix %s contains invalid character", prefix))
		}
		return MatchFunc(func(s string) bool { return strings.HasPrefix(s, prefix) }), nil
	}

	return nil, errors.New("invalid prefix or pattern")
}

func MustGetMatchFunc(a, b string) MatchFunc {
	fn, err := getMatchFunc(a, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getMatchFunc(): %v\n", err)
		os.Exit(1)
	}
	return fn
}

func generateSeeds(count int) [][]byte {
	seeds := make([][]byte, count)
	for i := 0; i < count; i++ {
		seeds[i] = make([]byte, 32)
		_, err := rand.Read(seeds[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read seed data: %s\n", err)
			os.Exit(1)
		}
	}
	return seeds
}

func pubkeyAddrFromSeed(seed []byte) (pubkey [65]byte, addr string) {
	pubkey[0] = 0x04
	var x, y *big.Int = s256.ScalarBaseMult(seed)
	xb, yb := x.Bytes(), y.Bytes()
	copy(pubkey[1+32-len(xb):], xb)
	copy(pubkey[1+64-len(yb):], yb)
	return pubkey, base58.CheckEncode(btcutil.Hash160(pubkey[:]), net.PubKeyHashAddrID)
}

func printMatch(m *VanityAddr) {
	elapsedTime := time.Since(beginTime)
	atomic.AddUint64(&numFound, 1)
	outmu.Lock()
	nf, ng := atomic.LoadUint64(&numFound), atomic.LoadUint64(&numGenerated)
	fmt.Printf("elapsed=%s addr=%s wif=%s pubkey=%s numfound=%d numgenerated=%d addresses/sec=%v\n",
		elapsedTime, m.addr, m.wif.String(), hex.EncodeToString(m.pubkey[:]), nf, ng, float64(ng)/elapsedTime.Seconds())
	outmu.Unlock()
}

func collectResults(in <-chan *VanityAddr) {
	go func() {
		for m := range in {
			printMatch(m)
		}
	}()
}

func generateAddresses(seed []byte) <-chan *VanityAddr {
	addrMatchFunc := MustGetMatchFunc(prefixFlag, patternFlag)
	out := make(chan *VanityAddr, np)
	go func() {
		for {
			pubkey, addr := pubkeyAddrFromSeed(seed)
			atomic.AddUint64(&numGenerated, 1)
			if addrMatchFunc(addr) {
				privkey, _ := btcec.PrivKeyFromBytes(s256, seed)
				wif, _ := btcutil.NewWIF(privkey, net, false)
				out <- &VanityAddr{
					pubkey:  pubkey,
					privkey: privkey,
					wif:     wif,
					addr:    addr,
					seed:    seed,
				}
			}
			seed[0]--
			for i := 0; seed[i] == 0; i++ {
				seed[i] = 255
				seed[i+1]--
			}
			runtime.Gosched()
		}
	}()
	return out
}

func main() {
	stopc := make(chan struct{})
	setupSignals(stopc)

	for _, seed := range generateSeeds(np * threadsPerCore) {
		out := generateAddresses(seed)
		collectResults(out)
	}

	<-stopc
}

func init() {
	flag.StringVar(&patternFlag, "pattern", "", "regexp pattern to match")
	flag.StringVar(&prefixFlag, "prefix", "", "prefix you want for your vanity address")
	flag.IntVar(&np, "j", runtime.NumCPU(), "number of processors to use")
	flag.IntVar(&threadsPerCore, "n", 1, "initial seeds to generate per core")
	flag.Parse()

	if len(patternFlag) == 0 && len(prefixFlag) == 0 {
		panic("Must supply either -pattern or -prefix")
	}

	runtime.GOMAXPROCS(np)

	// Panic on init if the assumptions used by the code change.
	if btcec.PubKeyBytesLenUncompressed != 65 {
		panic("Source code assumes 65-byte uncompressed secp256k1 " +
			"serialized public keys")
	}

	beginTime = time.Now()
	s256 = btcec.S256()
	net = &chaincfg.MainNetParams
}
