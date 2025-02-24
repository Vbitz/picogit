package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type pktLineReader struct {
	reader *bufio.Reader
}

func (r *pktLineReader) ReadLine() ([]byte, error) {
	var sizeHexBytes [4]byte
	if _, err := io.ReadFull(r.reader, sizeHexBytes[:]); err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, fmt.Errorf("failed to read size: %w", err)
	}

	var sizeBytes [2]byte

	if _, err := hex.Decode(sizeBytes[:], sizeHexBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to decode size: %w", err)
	}

	size := binary.BigEndian.Uint16(sizeBytes[:])
	if size == 0 {
		return nil, nil
	}

	line := make([]byte, size-4)
	if _, err := io.ReadFull(r.reader, line); err != nil {
		return nil, fmt.Errorf("failed to read line: %w", err)
	}

	return line, nil
}

func newPktLineReader(reader io.Reader) *pktLineReader {
	return &pktLineReader{
		reader: bufio.NewReader(reader),
	}
}

type pktLineWriter struct {
	writer io.Writer
}

func (w *pktLineWriter) Write(line []byte) (int, error) {
	size := len(line) + 4
	sizeHex := fmt.Sprintf("%04x", size)

	n, err := w.writer.Write([]byte(sizeHex))
	if err != nil {
		return n, err
	}

	return w.writer.Write(line)
}

func (w *pktLineWriter) Delimiter() error {
	n, err := w.writer.Write([]byte("0001"))
	if err != nil {
		return err
	}

	if n != 4 {
		return fmt.Errorf("failed to write delimiter")
	}

	return nil
}

func (w *pktLineWriter) Flush() error {
	n, err := w.writer.Write([]byte("0000"))
	if err != nil {
		return err
	}

	if n != 4 {
		return fmt.Errorf("failed to write flush")
	}

	return nil
}

func newPktLineWriter(writer io.Writer) *pktLineWriter {
	return &pktLineWriter{
		writer: writer,
	}
}

type gitObjectKind byte

const (
	gitObjectKindCommit   gitObjectKind = 1
	gitObjectKindTree     gitObjectKind = 2
	gitObjectKindBlob     gitObjectKind = 3
	gitObjectKindTag      gitObjectKind = 4
	gitObjectKindOfsDelta gitObjectKind = 6
	gitObjectKindRefDelta gitObjectKind = 7
)

func (g gitObjectKind) String() string {
	switch g {
	case gitObjectKindCommit:
		return "commit"
	case gitObjectKindTree:
		return "tree"
	case gitObjectKindBlob:
		return "blob"
	case gitObjectKindTag:
		return "tag"
	case gitObjectKindOfsDelta:
		return "ofs-delta"
	case gitObjectKindRefDelta:
		return "ref-delta"
	default:
		return "unknown"
	}
}

func (g gitObjectKind) Bytes() []byte {
	return []byte(g.String())
}

type packFileParser struct {
	reader *bufio.Reader
}

const (
	maskType        = 0b01110000
	maskContinue    = 0b10000000
	firstLengthBits = 4
)

// based on go-git (Apache 2.0 License)
func (p *packFileParser) readObjectHeader() (typ byte, len uint64, err error) {
	b, err := p.reader.ReadByte()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read object type: %w", err)
	}

	typ = b & maskType >> firstLengthBits

	// Extract the first part of the size (last 3 bits of the first byte).
	size := uint64(b & 0x0F)

	// |  001xxxx | xxxxxxxx | xxxxxxxx | ...
	//
	//	 ^^^       ^^^^^^^^   ^^^^^^^^
	//	Type      Size Part 1   Size Part 2
	//
	// Check if more bytes are needed to fully determine the size.
	if b&maskContinue != 0 {
		shift := uint(4)

		for {
			b, err := p.reader.ReadByte()
			if err != nil {
				return 0, 0, err
			}

			// Add the next 7 bits to the size.
			size |= uint64(b&0x7F) << shift

			// Check if the continuation bit is set.
			if b&maskContinue == 0 {
				break
			}

			// Prepare for the next byte.
			shift += 7
		}
	}
	return typ, size, nil
}

func (p *packFileParser) parse(repo *GitRepository) error {
	// read the header
	header := make([]byte, 4)
	if _, err := io.ReadFull(p.reader, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if !bytes.Equal(header, []byte("PACK")) {
		return fmt.Errorf("unexpected header: %s", header)
	}

	// read the version
	version := make([]byte, 4)
	if _, err := io.ReadFull(p.reader, version); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}

	if binary.BigEndian.Uint32(version) != 2 {
		return fmt.Errorf("unsupported version: %d", binary.BigEndian.Uint32(version))
	}

	// read the number of objects
	numObjectsBytes := make([]byte, 4)
	if _, err := io.ReadFull(p.reader, numObjectsBytes); err != nil {
		return fmt.Errorf("failed to read number of objects: %w", err)
	}

	numObjects := binary.BigEndian.Uint32(numObjectsBytes)

	hash := sha1.New()

	for i := uint32(0); i < numObjects; i++ {
		typ, len, err := p.readObjectHeader()
		if err != nil {
			return fmt.Errorf("failed to read object header: %w", err)
		}

		_ = len

		switch gitObjectKind(typ) {
		case gitObjectKindCommit:
			fallthrough
		case gitObjectKindTree:
			fallthrough
		case gitObjectKindBlob:
			fallthrough
		case gitObjectKindTag:
			hash.Reset()

			hash.Write(gitObjectKind(typ).Bytes())
			hash.Write([]byte(" "))
			hash.Write([]byte(strconv.FormatInt(int64(len), 10)))
			hash.Write([]byte("\x00"))

			buf := new(bytes.Buffer)

			zlibReader, err := zlib.NewReader(p.reader)
			if err != nil {
				return fmt.Errorf("failed to create zlib reader: %w", err)
			}

			if _, err := io.CopyN(io.MultiWriter(hash, buf), zlibReader, int64(len)); err != nil {
				return fmt.Errorf("failed to read object data: %w", err)
			}

			if err := zlibReader.Close(); err != nil {
				return fmt.Errorf("failed to close zlib reader: %w", err)
			}

			hashBytes := hash.Sum(nil)
			hashStr := hex.EncodeToString(hashBytes)

			repo.Objects[hashStr] = buf.Bytes()
		case gitObjectKindOfsDelta:
			return fmt.Errorf("unsupported object type: ofs-delta")
		case gitObjectKindRefDelta:
			return fmt.Errorf("unsupported object type: ref-delta")
		default:
			return fmt.Errorf("unsupported object type: %d", typ)
		}
	}

	return nil
}

type GitCommit struct {
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Message   string
}

type GitTreeEntry struct {
	Mode uint64
	Type gitObjectKind
	Hash string
	Name string
}

type GitTree struct {
	Entries []GitTreeEntry
}

type GitRepository struct {
	Head    string
	Objects map[string][]byte
}

func (r *GitRepository) Commit(hash string) (*GitCommit, error) {
	obj, ok := r.Objects[hash]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	reader := bytes.NewReader(obj)

	scanner := bufio.NewScanner(reader)

	commit := &GitCommit{}

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			for scanner.Scan() {
				commit.Message += scanner.Text() + "\n"
			}
			break
		}

		if strings.HasPrefix(line, "tree ") {
			commit.Tree = strings.TrimPrefix(line, "tree ")
		} else if strings.HasPrefix(line, "parent ") {
			commit.Parents = append(commit.Parents, strings.TrimPrefix(line, "parent "))
		} else if strings.HasPrefix(line, "author ") {
			commit.Author = strings.TrimPrefix(line, "author ")
		} else if strings.HasPrefix(line, "committer ") {
			commit.Committer = strings.TrimPrefix(line, "committer ")
		} else {
			return nil, fmt.Errorf("unexpected line: %s", line)
		}
	}

	return commit, nil
}

func (r *GitRepository) HeadCommit() (*GitCommit, error) {
	return r.Commit(r.Head)
}

func (r *GitRepository) Tree(hash string) (*GitTree, error) {
	obj, ok := r.Objects[hash]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	ret := &GitTree{}

	var ent []byte
	var hashBytes []byte
	for len(obj) > 0 {
		// read until \x00
		tokens := bytes.SplitN(obj, []byte("\x00"), 2)
		ent, obj = tokens[0], tokens[1]

		mode, name, ok := strings.Cut(string(ent), " ")
		if !ok {
			return nil, fmt.Errorf("unexpected entry format: %s", string(ent))
		}

		hashBytes, obj = obj[:20], obj[20:]

		modeInt, err := strconv.ParseUint(mode, 8, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mode: %w", err)
		}

		ret.Entries = append(ret.Entries, GitTreeEntry{
			Mode: modeInt,
			Type: gitObjectKindBlob,
			Hash: hex.EncodeToString(hashBytes),
			Name: name,
		})
	}

	return ret, nil
}

func (r *GitRepository) Blob(hash string) ([]byte, error) {
	obj, ok := r.Objects[hash]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", hash)
	}

	return obj, nil
}

func cloneRepo(urlString string) (*GitRepository, error) {
	parsed, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	uploadPackUrl := fmt.Sprintf("%s/info/refs?service=git-upload-pack", urlString)

	req, err := http.NewRequest(http.MethodGet, uploadPackUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "pico-git/0.1")
	req.Header.Set("Accept", "application/x-git-upload-pack-advertisement")
	// req.Header.Set("Git-Protocol", "version=2")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %s", resp.Status)
	}

	reader := newPktLineReader(resp.Body)

	// read and ignore the first line
	if _, err := reader.ReadLine(); err != nil {
		return nil, fmt.Errorf("error reading first line: %w", err)
	}

	refs := make(map[string]string)
	var caps []string

	for {
		line, err := reader.ReadLine()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("error reading line: %w", err)
		}

		if line == nil {
			continue
		}

		var part string
		if strings.ContainsRune(string(line), '\x00') {
			parts := strings.SplitN(string(line), "\x00", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("unexpected line format (caps line): len=%d %s", len(parts), string(line))
			}

			part = parts[0]

			if len(caps) == 0 {
				caps = strings.Split(strings.Trim(parts[1], "\n"), " ")
			}
		} else {
			part = string(line)
		}

		parts := strings.SplitN(strings.Trim(part, "\n"), " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unexpected line format (regular line): %s", string(line))
		}

		hash, ref := parts[0], parts[1]
		refs[ref] = hash
	}

	HEAD, ok := refs["HEAD"]
	if !ok {
		return nil, fmt.Errorf("HEAD not found in refs")
	}

	reqBuf := new(bytes.Buffer)
	writer := newPktLineWriter(reqBuf)

	writer.Write([]byte("command=fetch"))
	writer.Write([]byte("agent=pico-git/0.1"))
	writer.Write([]byte("object-format=sha1"))
	writer.Delimiter()
	writer.Write([]byte(fmt.Sprintf("want %s\n", HEAD)))
	writer.Write([]byte(fmt.Sprintf("want %s\n", HEAD)))
	writer.Write([]byte("done\n"))
	writer.Flush()

	req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/git-upload-pack", urlString), bytes.NewReader(reqBuf.Bytes()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("User-Agent", "pico-git/0.1")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Git-Protocol", "version=2")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %s", resp.Status)
	}

	reader2 := newPktLineReader(resp.Body)

	headerLine, err := reader2.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("error reading header line: %w", err)
	}

	if !bytes.Equal(headerLine, []byte("packfile\n")) {
		return nil, fmt.Errorf("unexpected header line: %s", headerLine)
	}

	packFile := new(bytes.Buffer)

	parser := &packFileParser{
		reader: bufio.NewReader(packFile),
	}

	for {
		line, err := reader2.ReadLine()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("error reading line: %w", err)
		}

		if line == nil {
			continue
		}

		if line[0] == '\x02' { // stderr
			os.Stderr.Write(line[1:])
		} else if line[0] == '\x01' { // stdout
			packFile.Write(line[1:])
		}
	}

	repo := &GitRepository{
		Objects: make(map[string][]byte),
		Head:    HEAD,
	}

	if err := parser.parse(repo); err != nil {
		return nil, err
	}

	return repo, nil
}

var (
	repoUrl = flag.String("repo", "http://forgejo:3000/joshua/hello.git", "URL of the repository to clone")
)

func appMain() error {
	flag.Parse()

	repo, err := cloneRepo(*repoUrl)
	if err != nil {
		return err
	}

	headCommit, err := repo.HeadCommit()
	if err != nil {
		return err
	}

	slog.Info("head commit", "commit", headCommit)

	tree, err := repo.Tree(headCommit.Tree)
	if err != nil {
		return err
	}

	slog.Info("tree", "tree", tree)

	for _, entry := range tree.Entries {
		slog.Info("entry", "entry", entry)
		content, err := repo.Blob(entry.Hash)
		if err != nil {
			return err
		}

		slog.Info("content", "content", string(content))
	}

	return nil
}

func main() {
	if err := appMain(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}
