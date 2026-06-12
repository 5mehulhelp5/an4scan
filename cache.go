package main

import (
	"encoding/gob"
	"hash/fnv"
	"os"
	"path/filepath"
	"sync"
)

// scanCache remembers files that were scanned clean (no findings) so
// subsequent runs can skip them if mtime+size are unchanged. Files with
// findings are always rescanned. The cache is invalidated whenever the
// signature set or scanner version changes.
type scanCache struct {
	Key     string
	Entries map[uint64][2]int64 // fnv64(relpath) -> {mtime unix, size}

	path  string
	dirty bool
	mu    sync.Mutex
}

type cacheFileFormat struct {
	Key     string
	Entries map[uint64][2]int64
}

func pathHash(rel string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(rel))
	return h.Sum64()
}

// cacheKey changes whenever anything that affects per-file findings changes.
func (s *An4Scanner) cacheKey() string {
	h := fnv.New64a()
	h.Write([]byte(version))
	h.Write([]byte(s.MinSeverity))
	for _, sig := range s.compiledSigs {
		h.Write([]byte(sig.ID))
		h.Write([]byte(sig.Regex.String()))
	}
	for _, fp := range s.compiledFilenames {
		h.Write([]byte(fp.Regex.String()))
	}
	for _, w := range s.Whitelist {
		h.Write([]byte(w))
	}
	return string(rune(0)) + string(h.Sum(nil))
}

func loadScanCache(root, key string) *scanCache {
	c := &scanCache{
		Key:     key,
		Entries: make(map[uint64][2]int64),
		path:    filepath.Join(root, ".an4scan", "filecache.gob"),
	}
	f, err := os.Open(c.path)
	if err != nil {
		return c
	}
	defer f.Close()

	var ff cacheFileFormat
	if err := gob.NewDecoder(f).Decode(&ff); err != nil || ff.Key != key {
		return c // corrupt or signature set changed: start fresh
	}
	c.Entries = ff.Entries
	return c
}

func (c *scanCache) isClean(rel string, mtime, size int64) bool {
	c.mu.Lock()
	e, ok := c.Entries[pathHash(rel)]
	c.mu.Unlock()
	return ok && e[0] == mtime && e[1] == size
}

func (c *scanCache) markClean(rel string, mtime, size int64) {
	c.mu.Lock()
	c.Entries[pathHash(rel)] = [2]int64{mtime, size}
	c.dirty = true
	c.mu.Unlock()
}

func (c *scanCache) save() error {
	if !c.dirty {
		return nil
	}
	os.MkdirAll(filepath.Dir(c.path), 0755)
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	err = gob.NewEncoder(f).Encode(cacheFileFormat{Key: c.Key, Entries: c.Entries})
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, c.path)
}
