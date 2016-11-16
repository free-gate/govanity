package main

import (
    "syscall"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
    "os/signal"
	"strings"
	"time"
    "sync"
    "sync/atomic"
    "runtime"
    "regexp"
    "errors"
    "encoding/hex"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

var (
    beginTime time.Time
    s256 *btcec.KoblitzCurve
	net *chaincfg.Params
	numFound uint64
    numGenerated uint64
    np int
    prefixFlag string
    patternFlag string
    outmu sync.Mutex
)

type MatchFunc func(s string) bool

func composeOr(f MatchFunc, g MatchFunc) MatchFunc {
    return MatchFunc(func(s string) bool {
        return f(s) || g(s)
    })
}


func getMatchFunc(prefix string, pattern string) (fn MatchFunc, err error) {
    fn = MatchFunc(func(s string) bool { return false })

    if len(pattern) > 0 {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return nil, errors.New(fmt.Sprintf("must supply valid regexp: %v\n", err))
        }
        fn = composeOr(fn, MatchFunc(func(s string) bool { return re.MatchString(s) }))
    }

    if len(prefix) > 0 {
        if len(prefix) < 1 || len(prefix) > 34 {
            return nil, errors.New(fmt.Sprintf("prefix %s has invalid length %d", prefix, len(prefix)))
        } else if strings.ContainsAny(prefix, "0IOl`~-_=+[{]}\\|;:'\",<.>/?!@#$%^&*()") {
            return nil, errors.New(fmt.Sprintf("prefix %s contains invalid character", prefix))
        }
        fn = composeOr(fn, MatchFunc(func(s string) bool { return strings.HasPrefix(s, prefix) }))
    }

    return fn, nil
}

func generateSeeds(np int) [][]byte {
    seeds := make([][]byte, np)
    for i := 0; i < np; i++ {
        seeds[i] = make([]byte, 32)
        _, err := rand.Read(seeds[i])
        if err != nil {
            fmt.Fprintf(os.Stderr, "failed to read seed data: %s\n", err)
            os.Exit(1)
        }
    }
    return seeds
}

func setupSignals(stopc chan<- struct{}) {
    ctrlc := make(chan os.Signal, 2)

    signal.Notify(ctrlc, os.Interrupt, syscall.SIGTERM)
    go func(stopc chan<- struct{}) {
        <-ctrlc
        stopc <- struct{}{}
    }(stopc)
}

func MustGetMatchFunc(a, b string) MatchFunc {
    fn, err := getMatchFunc(a, b)
    if err != nil {
        fmt.Fprintf(os.Stderr, "getMatchFunc(): %v\n", err)
        os.Exit(1)
    }
    return fn
}

func pubkeyAddrFromSeed(seed []byte) (pubkey [65]byte, addr string) {
    pubkey[0] = 0x04
    var x, y *big.Int = s256.ScalarBaseMult(seed)
    xb, yb := x.Bytes(), y.Bytes()
    copy(pubkey[1 + 32 - len(xb):], xb)
    copy(pubkey[1 + 64 - len(yb):], yb)
    return pubkey, base58.CheckEncode(btcutil.Hash160(pubkey[:]), net.PubKeyHashAddrID)
}

func printMatch(pubkey [65]byte, addr string, seed []byte) {
    privkey, _ := btcec.PrivKeyFromBytes(s256, seed)
    wif, _ := btcutil.NewWIF(privkey, net, false)
    elapsedTime := time.Since(beginTime)
    atomic.AddUint64(&numFound, 1)
    outmu.Lock()
    nf, ng := atomic.LoadUint64(&numFound), atomic.LoadUint64(&numGenerated)
    fmt.Printf("elapsed=%s addr=%s wif=%s pubkey=%s numfound=%d numgenerated=%d addresses/sec=%v\n",
               elapsedTime, addr, wif.String(), hex.EncodeToString(pubkey[:]), nf, ng, float64(ng)/elapsedTime.Seconds())
    outmu.Unlock()
}

func collectResults(in <-chan VanityAddr) {
    go func() {
        for v := range in {
            printMatch(v.pubkey, v.addr, v.seed)
        }
    }()
}

func generateAddresses(seed []byte) <-chan VanityAddr {
    addrMatchFunc := MustGetMatchFunc(prefixFlag, patternFlag)
    out := make(chan VanityAddr, np)
    go func() {
        for {
            pubkey, addr := pubkeyAddrFromSeed(seed)
            atomic.AddUint64(&numGenerated, 1)
            if addrMatchFunc(addr) {
                out <- VanityAddr{pubkey, addr, seed}
            }
            seed[0]--
            for i := 0; seed[i] == 0; i++ {
                seed[i] = 255
                seed[i+1]--
            }
        }
    }()
    return out
}

type VanityAddr struct {
    pubkey [65]byte
    addr string
    seed []byte
}

func main() {
    stopc := make(chan struct{})
    setupSignals(stopc)


    for _, seed := range generateSeeds(np) {
        out := generateAddresses(seed)
        collectResults(out)
    }

    <-stopc
}

func init() {
    flag.StringVar(&patternFlag, "pattern", "", "regexp pattern to match")
	flag.StringVar(&prefixFlag, "prefix", "", "prefix you want for your vanity address")
	flag.IntVar(&np, "j", runtime.NumCPU(), "number of processors to use")
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
