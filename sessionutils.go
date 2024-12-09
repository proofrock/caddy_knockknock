package caddy_knockknock

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

var mutex sync.Mutex
var sessions map[string]string = make(map[string]string)
var lastAccesses map[string]int64 = make(map[string]int64)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func genRandomString(length int) string {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		result[i] = alphabet[n.Int64()]
	}
	return string(result)
}

func newSession(ip string) string {
	ses := genRandomString(33)

	mutex.Lock()
	defer mutex.Unlock()

	sessions[ip] = ses
	lastAccesses[ip] = time.Hour.Milliseconds()
	return ses
}

func getSession(ip string) string {
	mutex.Lock()
	defer mutex.Unlock()

	lastAccesses[ip] = time.Hour.Milliseconds()
	return sessions[ip]
}

func cleanupStaleSessions() {
	mutex.Lock()
	defer mutex.Unlock()

	cutoffTime := time.Now().Add(-15 * time.Minute).UnixMilli()
	for ip, lastAccess := range lastAccesses {
		if lastAccess < cutoffTime {
			delete(sessions, ip)
			delete(lastAccesses, ip)
		}
	}
}

func init() {
	// Setup periodic cleanup
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			cleanupStaleSessions()
		}
	}()
}
