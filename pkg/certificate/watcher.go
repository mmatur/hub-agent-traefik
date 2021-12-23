package certificate

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Certificate contains a TLS certificate and its private key.
type Certificate struct {
	Cert string
	Key  string
}

// UpdateFunc is a function called when certificates are modified.
type UpdateFunc func(certs []Certificate) error

// Watcher watches TLS certificates and calls an UpdateFunc when there is a change.
type Watcher struct {
	refreshInterval time.Duration
	certsDir        string

	updateFuncs []UpdateFunc
}

// NewWatcher returns a new watcher to track TLS certificates.
func NewWatcher(certsDir string, funcs ...UpdateFunc) *Watcher {
	return &Watcher{
		refreshInterval: 5 * time.Second,
		certsDir:        certsDir,
		updateFuncs:     funcs,
	}
}

// Run runs the watcher.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.refreshInterval)
	defer t.Stop()

	var previous []Certificate

	log.Info().Str("directory", w.certsDir).Msg("Starting certificates watcher")

	for {
		select {
		case <-t.C:
			certs, err := readCertsDir(w.certsDir)
			if err != nil {
				log.Error().Err(err).Str("directory", w.certsDir).Msg("Unable to read certificates from directory")
				continue
			}

			if reflect.DeepEqual(previous, certs) {
				continue
			}

			log.Debug().Msg("Executing certificates watcher callbacks")

			var errs []error
			for _, fn := range w.updateFuncs {
				if err = fn(certs); err != nil {
					errs = append(errs, err)
					continue
				}
			}

			if len(errs) > 0 {
				log.Error().Errs("errors", errs).Msg("Unable to execute certificates watcher callbacks")
			}

			previous = certs

		case <-ctx.Done():
			return
		}
	}
}

func readCertsDir(dir string) ([]Certificate, error) {
	var certs []Certificate

	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Arbitrarily skipping key files as we load them as pairs and this would result in duplicates.
		ext := filepath.Ext(path)
		if ext == ".key" {
			return nil
		}

		prefix := strings.TrimSuffix(path, ext)

		certFilePath := prefix + ".crt"
		certContent, err := os.ReadFile(certFilePath)
		if err != nil {
			return fmt.Errorf("read certificate file %q: %w", certFilePath, err)
		}

		keyFilePath := prefix + ".key"
		keyContent, err := os.ReadFile(keyFilePath)
		if err != nil {
			return fmt.Errorf("read key file %q: %w", keyFilePath, err)
		}

		certs = append(certs, Certificate{
			Key:  string(keyContent),
			Cert: string(certContent),
		})

		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return certs, nil
}
