// Copyright (c) 2016 Tamás Gulácsi
//
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"

	"github.com/kr/binarydist"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/admpub/overseer-bindiff/fetcher"
)

const DefaultRSABits = 4096

func main() {
	fetcher.Logf = log.Printf

	genDir := "public"
	flag.StringVar(&genDir, "o", genDir, "Output directory for writing updates")

	goos := os.Getenv("GOOS")
	goarch := os.Getenv("GOARCH")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	cmdMain := &cobra.Command{
		Use: "main",
	}

	var infoPath, diffPath, binPath, keyringPath string
	cmdGenerate := &cobra.Command{
		Use: "generate",
		Run: func(_ *cobra.Command, args []string) {
			appPath, err := getAppPath(args[0])
			if err != nil {
				log.Fatal(err)
			}

			var keyring openpgp.EntityList
			if keyringPath != "" {
				fh, err := os.Open(keyringPath)
				if err != nil {
					log.Fatal(err)
				}
				keyring, err = openpgp.ReadArmoredKeyRing(fh)
				fh.Close()
				if err != nil {
					log.Fatal(err)
				}
			}
			var tpl fetcher.Templates
			if err := tpl.Init(infoPath, diffPath, binPath); err != nil {
				log.Fatal(err)
			}
			os.MkdirAll(genDir, 0755)

			src, err := os.Open(appPath)
			if err != nil {
				log.Fatal(errors.Wrapf(err, "open %q", appPath))
			}
			err = createUpdate(genDir, tpl, src,
				fetcher.Platform{GOOS: goos, GOARCH: goarch},
				keyring,
			)
			src.Close()
			if err != nil {
				log.Fatal(err)
			}
			return
		},
	}
	F := cmdGenerate.Flags()
	F.StringVar(&goos, "os", goos,
		"Target OS. Defaults to running os or the environment variable GOOS.")
	F.StringVar(&goarch, "arch", goarch,
		"Target ARCH. Defaults to running arch or the environment variable GOARCH.")
	F.StringVar(&infoPath, "info", fetcher.DefaultInfoPath, "info path template")
	F.StringVar(&diffPath, "diff", fetcher.DefaultDiffPath, "diff path template")
	F.StringVar(&binPath, "bin", fetcher.DefaultBinPath, "binary path template")
	F.StringVar(&keyringPath, "keyring", "", "gpg keyring to use")
	cmdMain.AddCommand(cmdGenerate)

	{
		var out string
		cmdGenKeys := &cobra.Command{
			Use: "genkeys",
			Run: func(_ *cobra.Command, args []string) {
				if len(args) < 2 {
					fmt.Fprintf(os.Stderr, "Producer and consumer email addresses is a must!\n")
					os.Exit(1)
				}
				w := io.WriteCloser(os.Stdout)
				if !(out == "" || out == "-") {
					var err error
					if w, err = os.Create(out); err != nil {
						log.Fatal(err)
					}
				}
				defer func() {
					if err := w.Close(); err != nil {
						log.Fatal(err)
					}
				}()
				if err := genAndSer(w, args[0], "Producer", "overseer-bindiff", ""); err != nil {
					log.Fatal(err)
				}
				if err := genAndSer(w, args[1], "Consumer", "overseer-bindiff", ""); err != nil {
					log.Fatal(err)
				}
			},
		}
		cmdGenKeys.Flags().StringVarP(&out, "output", "o", "-", "output file name")
		cmdMain.AddCommand(cmdGenKeys)
	}

	var goOut bool
	cmdPrintKeys := &cobra.Command{
		Use:     "printkeys",
		Aliases: []string{"printkey", "key"},
		Run: func(_ *cobra.Command, args []string) {
			r := io.ReadCloser(os.Stdin)
			if len(args) > 0 && args[0] != "" && args[0] != "-" {
				var err error
				r, err = os.Open(args[0])
				if err != nil {
					log.Fatal(err)
				}
			}
			defer r.Close()
			var el openpgp.EntityList
			for {
				els, err := openpgp.ReadArmoredKeyRing(r)
				el = append(el, els...)
				if err != nil {
					if len(el) == 0 {
						log.Fatal(err)
					}
					break
				}
			}
			if goOut {
				fmt.Printf(`package main

import (
	"io"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// readKeyring reads the keyring, and panics on error
func readKeyring(r io.Reader) openpgp.KeyRing {
	var keyring openpgp.EntityList
	for {
		el, err := openpgp.ReadArmoredKeyRing(r)
		if err != nil {
			if len(keyring) == 0 {
				panic(err)
			}
			break
		}
		keyring = append(keyring, el...)
	}
    return keyring
}

var keyring = readKeyring(strings.NewReader(
` + "`")
			}
			// Print all publick keys.
			for _, e := range el {
				if err := serialize(os.Stdout, e, openpgp.PublicKeyType); err != nil {
					log.Fatal(err)
				}
			}
			// Search for the consumer's private key
			for _, k := range el.DecryptionKeys() {
				var isConsumer bool
				for nm := range k.Entity.Identities {
					if isConsumer = strings.Contains(strings.ToLower(nm), "consumer"); isConsumer {
						break
					}
				}
				if !isConsumer {
					continue
				}
				if err := serialize(os.Stdout, k.Entity, openpgp.PrivateKeyType); err != nil {
					log.Fatal(err)
				}
				break
			}
			if goOut {
				fmt.Printf("`))\n")
			}
			os.Stdout.Close()
		},
	}
	cmdPrintKeys.Flags().BoolVar(&goOut, "go-out", false, "go output, not just the armored keyring")
	cmdMain.AddCommand(cmdPrintKeys)

	if _, _, err := cmdMain.Find(os.Args[1:]); err != nil {
		os.Args = append(append(make([]string, 0, len(os.Args)+1), os.Args[0], "generate"), os.Args[1:]...)
	}
	cmdMain.Execute()
}

func genAndSer(w io.Writer, nce, defName, defComment, defEmail string, confs ...PackConf) error {
	name, comment, email := splitNCE(nce, defName, defComment, defEmail)
	conf := &packet.Config{RSABits: DefaultRSABits}
	for _, f := range confs {
		f(conf)
	}
	e, err := openpgp.NewEntity(name, comment, email, conf)
	if err != nil {
		return errors.Wrapf(err, "NewEntity(%q, %q, %q)", name, comment, email)
	}
	for _, blockType := range []string{openpgp.PrivateKeyType, openpgp.PublicKeyType} {
		if err := serialize(w, e, blockType); err != nil {
			return err
		}
	}
	return nil
}

type PackConf func(*packet.Config)

func WithRSABits(bits int) func(c *packet.Config) {
	if bits == 0 {
		bits = DefaultRSABits
	}
	return func(c *packet.Config) { c.RSABits = bits }
}

func serialize(w io.Writer, e *openpgp.Entity, blockType string) error {
	var buf bytes.Buffer
	wc, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return errors.Wrap(err, blockType)
	}
	if blockType == openpgp.PrivateKeyType {
		err = e.SerializePrivate(wc, nil)
	} else {
		err = e.Serialize(wc)
	}
	if closeErr := wc.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.Wrap(err, "SerializePrivate")
	}
	if _, err = w.Write([]byte{'\n'}); err != nil {
		return err
	}
	b := buf.Bytes()
	i := bytes.Index(b, []byte("-----\n")) + 6
	var nm string
	for k := range e.Identities {
		nm = k
		break
	}
	_, err = io.Copy(w,
		io.MultiReader(bytes.NewReader(b[:i]),
			strings.NewReader("Name: "+nm+"\n"),
			bytes.NewReader(b[i:])))
	return err
}

func splitNCE(nce, defName, defComment, defEmail string) (name, comment, email string) {
	nce = strings.TrimSpace(nce)
	name, comment, email = defName, defComment, defEmail
	if i := strings.LastIndex(nce, "@"); i >= 0 {
		if j := strings.LastIndexAny(nce[:i], "< "); j < 0 {
			return name, comment, nce
		} else {
			email, nce = nce[j+1:], strings.TrimSpace(nce[:j])
		}
	}
	if strings.HasSuffix(nce, ")") {
		if i := strings.LastIndex(nce, "("); i >= 0 {
			comment, nce = nce[i+1:len(nce)-1], strings.TrimSpace(nce[i:])
		}
	}
	name = nce
	if name == "" {
		name = defName
	}
	return name, comment, email
}

func createUpdate(genDir string, tpl fetcher.Templates, src io.ReadSeeker, plat fetcher.Platform, keyring openpgp.EntityList) error {
	// generate the sha256 of the binary
	h := fetcher.NewSha()
	if _, err := io.Copy(h, src); err != nil {
		return errors.Wrapf(err, "hash %q", src)
	}
	if _, err := src.Seek(0, 0); err != nil {
		return errors.Wrapf(err, "seek back to the beginning of %q", src)
	}
	var mtime time.Time
	if str, ok := src.(interface {
		Stat() (os.FileInfo, error)
	}); ok {
		if fi, err := str.Stat(); err == nil {
			mtime = fi.ModTime()
		}
	}
	newSha := h.Sum(nil)
	info := fetcher.URLInfo{
		Platform:    plat,
		NewSha:      fetcher.EncodeSha(newSha),
		IsEncrypted: keyring != nil,
	}

	// gzip the binary to its destination
	binPath, err := tpl.Execute(tpl.Bin, info)
	if err != nil {
		return errors.Wrapf(err, "execute bin template")
	}
	binPathNE := binPath
	if info.IsEncrypted {
		infoNE := info
		infoNE.IsEncrypted = false
		binPathNE, _ = tpl.Execute(tpl.Bin, infoNE)
	}

	binPath = filepath.Join(genDir, binPath)
	log.Printf("Writing binary to %q.", binPath)
	os.MkdirAll(filepath.Dir(binPath), 0755)
	fh, err := os.Create(binPath)
	if err != nil {
		return errors.Wrapf(err, "create %q", binPath)
	}
	defer fh.Close()
	wc := io.WriteCloser(fh)
	if keyring != nil {
		if wc, err = encrypt(fh, binPathNE, mtime, keyring); err != nil {
			return errors.Wrap(err, "Encrypt")
		}
	}
	w := gzip.NewWriter(wc)
	if _, err := io.Copy(w, src); err != nil {
		return errors.Wrapf(err, "gzip %q into %q", src, fh.Name())
	}
	if err := w.Close(); err != nil {
		return errors.Wrapf(err, "flush gzip into %q", fh.Name())
	}
	if keyring != nil {
		if err := wc.Close(); err != nil {
			return err
		}
	}
	if err := fh.Close(); err != nil {
		return errors.Wrapf(err, "close %q", fh.Name())
	}

	// write info.json
	infoPath, err := tpl.Execute(tpl.Info, info)
	if err != nil {
		return errors.Wrapf(err, "execute info template")
	}
	infoPath = filepath.Join(genDir, infoPath)
	log.Printf("Writing info to %q.", infoPath)
	os.MkdirAll(filepath.Dir(infoPath), 0755)
	fh, err = os.Create(infoPath)
	if err != nil {
		return errors.Wrapf(err, "create %q", infoPath)
	}
	var buf bytes.Buffer
	err = json.NewEncoder(io.MultiWriter(fh, &buf)).
		Encode(fetcher.Info{Sha256: newSha})
	if closeErr := fh.Close(); closeErr != nil && err == nil {
		err = errors.Wrapf(err, "close info %q", fh.Name())
	}
	if err != nil {
		return errors.Wrapf(err, "encode %v into %q", newSha, fh.Name())
	}

	if keyring != nil {
		fh, err := os.Create(fh.Name() + ".asc")
		if err != nil {
			return err
		}
		log.Printf("Signing %q", buf.String())
		err = openpgp.ArmoredDetachSign(fh,
			fetcher.SignerKey(keyring),
			bytes.NewReader(buf.Bytes()), nil)
		if closeErr := fh.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}

	info.OldSha = oldShaPlaceholder
	diffPath, err := tpl.Execute(tpl.Diff, info)
	if err != nil {
		return errors.Wrapf(err, "execute diff template")
	}
	return generateDiffs(filepath.Join(genDir, diffPath), binPath, keyring)
}

func encrypt(w io.Writer, fn string, mtime time.Time, keyring openpgp.EntityList) (io.WriteCloser, error) {
	wc, err := openpgp.Encrypt(
		w, keyring, fetcher.SignerKey(keyring),
		&openpgp.FileHints{IsBinary: true, FileName: fn, ModTime: mtime},
		&packet.Config{DefaultCompressionAlgo: 0, RSABits: DefaultRSABits},
	)
	return wc, errors.Wrap(err, "Encrypt")
}

const oldShaPlaceholder = "{{OLDSHA}}"

// generateDiffs calculates and writes the differences between the current
// binary and the old binaries, into diffPath.
//
// binPath must be the current binary's filename (with full path),
// and the old binaries are searched in that directory;
//
// diffPath should be the full path for the difference between the current
// binary and the binary named as oldShaPlaceholder.
func generateDiffs(diffPath, binPath string, keyring openpgp.KeyRing) error {
	hasKeyring := fetcher.HasKeys(keyring)
	binDir, currentName := filepath.Split(binPath)
	files, err := ioutil.ReadDir(binDir)
	if err != nil {
		return errors.Wrapf(err, "read %q", binDir)
	}
	getSha := func(fn string) string {
		fn = filepath.Base(fn)
		if hasKeyring {
			fn = strings.TrimSuffix(fn, ".gpg")
		}
		if ext := filepath.Ext(fn); ext != "" {
			return fn[:len(fn)-len(ext)]
		}
		return fn
	}

	currentRaw, err := os.Open(binPath)
	if err != nil {
		return errors.Wrapf(err, "open %q", binPath)
	}
	defer currentRaw.Close()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Name() == currentName {
			continue
		}
		oldSha := getSha(file.Name())

		fn := filepath.Join(binDir, file.Name())
		log.Printf("Calculating diff between %q and %q.", fn, binPath)
		diffName := strings.Replace(diffPath, oldShaPlaceholder, oldSha, -1)

		old, err := openBin(fn, keyring)
		if err != nil {
			log.Println(err)
			continue
		}
		cur, err := openBin(binPath, keyring)
		if err != nil {
			log.Fatal(err)
		}

		emptyDir(filepath.Dir(diffName))
		os.MkdirAll(filepath.Dir(diffName), 0755)

		diff, err := os.Create(diffName)
		if err != nil {
			old.Close()
			cur.Close()
			return errors.Wrapf(err, "create %q", diffName)
		}
		err = binarydist.Diff(old, cur, diff)
		old.Close()
		cur.Close()
		if err != nil {
			return errors.Wrapf(err, "calculate binary diffs and write into %q", diff.Name())
		}
		if err := diff.Close(); err != nil {
			return errors.Wrapf(err, "close %q", diff.Name())
		}
	}
	return nil
}

func openBin(fn string, keyring openpgp.KeyRing) (io.ReadCloser, error) {
	hasKeyring := fetcher.HasKeys(keyring)
	fh, err := os.Open(fn)
	if err != nil {
		return nil, errors.Wrapf(err, "open %q", fn)
	}

	rc := io.ReadCloser(fh)
	if hasKeyring {
		r, err := decrypt(rc, keyring)
		if err != nil {
			fh.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{r, fh}, nil
	}

	gr, err := gzip.NewReader(rc)
	if err != nil {
		fh.Close()
		return nil, errors.Wrapf(err, "gzip decode %q", fn)
	}
	return struct {
		io.Reader
		io.Closer
	}{gr, rc}, nil
}

func decrypt(r io.Reader, keyring openpgp.KeyRing) (io.Reader, error) {
	md, err := openpgp.ReadMessage(r, keyring, fetcher.KeyPrompt, nil)
	if err != nil {
		return r, errors.Wrap(err, "decrypt")
	}
	return md.UnverifiedBody, nil
}

func printUsage() {
	fmt.Println(`
Positional arguments:
	Single platform: go-selfupdate myapp
	Cross platform: go-selfupdate /tmp/mybinares/`)
}

func emptyDir(path string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return errors.Wrapf(err, "read dir %q", path)
	}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		fn := filepath.Join(path, fi.Name())
		log.Printf("Deleting %q.", fn)
		os.Remove(fn)
	}
	return nil
}

func getAppPath(appPath string) (string, error) {
	if !filepath.IsAbs(appPath) {
		if filepath.Base(appPath) == appPath { // search PATH
			var err error
			if appPath, err = exec.LookPath(appPath); err != nil {
				log.Fatal(err)
			}
		} else {
			wd, err := os.Getwd()
			if err != nil {
				log.Fatal(err)
			}
			appPath = filepath.Clean(filepath.Join(wd, appPath))
		}
	}
	_, err := os.Stat(appPath)
	return appPath, err
}
