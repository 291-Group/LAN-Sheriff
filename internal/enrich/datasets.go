package enrich

import (
	"compress/gzip"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Datasets vendored into the binary at build time by `make datasets`. The
// directory holds only a README in a fresh checkout, so the pattern always
// matches and the build never depends on a downloaded file being present.
//
// A release binary carries the country database and therefore paints the map
// offline on first run. A development build falls back to fetching it (see
// Manager.ensure), which costs a few seconds of "locating..." on first launch
// and nothing thereafter.
//
//go:embed data
var embedded embed.FS

// DB-IP Lite datasets are published monthly under CC BY 4.0, which obliges us
// to attribute them in the UI and the README.
const dbipBase = "https://download.db-ip.com/free/"

// datasetsFor returns the datasets to use for a given month, newest first. The
// current month's file does not exist until DB-IP publishes it, so the resolver
// walks backwards until something is available.
func datasetsFor(kind string, t time.Time) []string {
	var urls []string
	for i := 0; i < 3; i++ {
		m := t.AddDate(0, -i, 0)
		urls = append(urls, fmt.Sprintf("%sdbip-%s-lite-%04d-%02d.mmdb.gz",
			dbipBase, kind, m.Year(), int(m.Month())))
	}
	return urls
}

const (
	fileCountry = "dbip-country-lite.mmdb"
	fileASN     = "dbip-asn-lite.mmdb"
	fileCity    = "dbip-city-lite.mmdb"
)

// Manager resolves enrichment datasets: embedded if the build carries them,
// otherwise from the data directory, otherwise fetched in the background.
type Manager struct {
	dir    string
	client *http.Client
	// WithCity fetches the city-precision database. 62 MB compressed, and
	// **125 MB once written**, which is the number that matters on a small card:
	// measured on a Raspberry Pi, where the three datasets together come to
	// 142 MB. The flag help says both, because a user deciding whether to fetch
	// it is deciding about disk, not about bandwidth.
	WithCity bool
}

// NewManager returns a dataset manager rooted at dir.
func NewManager(dir string) *Manager {
	return &Manager{
		dir:    dir,
		client: &http.Client{Timeout: 10 * time.Minute},
	}
}

// Path returns the on-disk location for a dataset file.
func (m *Manager) Path(name string) string { return filepath.Join(m.dir, name) }

// Open returns a reader for a dataset, preferring the copy on disk and falling
// back to one embedded in the binary. It returns fs.ErrNotExist when neither
// exists yet, which callers treat as "not ready", never as fatal.
func (m *Manager) Open(name string) (string, error) {
	p := m.Path(name)
	if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
		return p, nil
	}
	// Materialise the embedded copy into the data dir so the mmdb reader can
	// mmap it like any other file.
	b, err := embedded.ReadFile("data/" + name)
	if err != nil {
		return "", fs.ErrNotExist
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return "", err
	}
	if err := writeAtomic(p, b); err != nil {
		return "", err
	}
	slog.Info("unpacked embedded dataset", "name", name)
	return p, nil
}

// Ensure fetches any missing datasets. It is meant to run in the background:
// every failure is logged and swallowed, because a missing dataset degrades the
// map to "location unknown" rather than stopping the application.
func (m *Manager) Ensure(ctx context.Context) {
	want := []struct {
		file string
		kind string
		skip bool
	}{
		{fileCountry, "country", false},
		{fileASN, "asn", false},
		{fileCity, "city", !m.WithCity},
	}

	for _, w := range want {
		if w.skip {
			continue
		}
		if _, err := m.Open(w.file); err == nil {
			continue
		}
		if err := m.fetch(ctx, w.file, datasetsFor(w.kind, time.Now())); err != nil {
			slog.Warn("could not fetch enrichment dataset",
				"dataset", w.kind, "err", err,
				"effect", "endpoints will show without this detail until it succeeds")
			continue
		}
		slog.Info("enrichment dataset ready", "dataset", w.kind)
	}
}

func (m *Manager) fetch(ctx context.Context, name string, urls []string) error {
	var lastErr error
	for _, url := range urls {
		err := m.fetchOne(ctx, name, url)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no candidate URLs")
	}
	return lastErr
}

func (m *Manager) fetchOne(ctx context.Context, name, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.dir, name+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	// Cap the decompressed size so a bad or hostile response cannot fill the
	// disk we promised to keep bounded.
	const maxSize = 512 << 20
	n, err := io.Copy(tmp, io.LimitReader(gz, maxSize))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s: empty response", url)
	}
	return os.Rename(tmpName, m.Path(name))
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
