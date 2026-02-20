package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeka/zip"
)

var crc32Tab [256]uint32

var (
	mul3 = [10]int{0, 3, 6, 9, 2, 5, 8, 1, 4, 7}
	mul7 = [10]int{0, 7, 4, 1, 8, 5, 2, 9, 6, 3}
	mul9 = [10]int{0, 9, 8, 7, 6, 5, 4, 3, 2, 1}
)

func init() {
	for i := range crc32Tab {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = (c >> 1) ^ 0xedb88320
			} else {
				c >>= 1
			}
		}
		crc32Tab[i] = c
	}
}

// zipCryptoDecryptor decrypts ZipCrypto-encrypted data using a running key state.
// Implements io.Reader so it can feed directly into compress/flate.
type zipCryptoDecryptor struct {
	src        []byte
	pos        int
	k0, k1, k2 uint32
}

func (d *zipCryptoDecryptor) Read(p []byte) (int, error) {
	avail := len(d.src) - d.pos
	if avail <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > avail {
		n = avail
	}
	for i := 0; i < n; i++ {
		temp := d.k2 | 2
		p[i] = d.src[d.pos] ^ byte((temp*(temp^1))>>8)
		d.k0 = crc32Tab[(d.k0^uint32(p[i]))&0xff] ^ (d.k0 >> 8)
		d.k1 = (d.k1 + (d.k0 & 0xff)) * 0x08088405 + 1
		d.k2 = crc32Tab[(d.k2^(d.k1>>24))&0xff] ^ (d.k2 >> 8)
		d.pos++
	}
	return n, nil
}

func (d *zipCryptoDecryptor) reset(k0, k1, k2 uint32) {
	d.pos = 0
	d.k0, d.k1, d.k2 = k0, k1, k2
}

type dateTask struct {
	year, month, day int
}

type zipTarget struct {
	encHeader   [12]byte
	crcCheck    byte
	timeCheck   byte
	compData    []byte // compressed payload (after 12-byte encryption header)
	expectedCRC uint32
}

func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}

func peselMonthCode(y, m int) int {
	if y >= 2000 {
		return m + 20
	}
	return m
}

func generateDates(ch chan<- dateTask, found *atomic.Bool) {
	defer close(ch)
	now := time.Now()
	ty, tm, td := now.Year(), int(now.Month()), now.Day()

	fy, fm, fd := 1977, 1, 1
	by, bm, bd := 1976, 12, 31

	next := func(y, m, d int) (int, int, int) {
		d++
		if d > daysInMonth(y, m) {
			d = 1
			m++
			if m > 12 {
				m = 1
				y++
			}
		}
		return y, m, d
	}

	prev := func(y, m, d int) (int, int, int) {
		d--
		if d < 1 {
			m--
			if m < 1 {
				m = 12
				y--
			}
			d = daysInMonth(y, m)
		}
		return y, m, d
	}

	fDone, bDone := false, false
	for !fDone || !bDone {
		if found.Load() {
			return
		}
		if !fDone {
			if fy > ty || (fy == ty && fm > tm) || (fy == ty && fm == tm && fd > td) {
				fDone = true
			} else {
				ch <- dateTask{fy, fm, fd}
				fy, fm, fd = next(fy, fm, fd)
			}
		}
		if found.Load() {
			return
		}
		if !bDone {
			if by < 1900 {
				bDone = true
			} else {
				ch <- dateTask{by, bm, bd}
				by, bm, bd = prev(by, bm, bd)
			}
		}
	}
}

func zipCryptoPrecompute(dateBytes [6]byte) (k0, k1, k2 uint32) {
	k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
	for i := 0; i < 6; i++ {
		k0 = crc32Tab[(k0^uint32(dateBytes[i]))&0xff] ^ (k0 >> 8)
		k1 = (k1 + (k0 & 0xff)) * 0x08088405 + 1
		k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
	}
	return
}

func fastWorker(
	target *zipTarget,
	ch <-chan dateTask, found *atomic.Bool, counter *atomic.Int64, resultCh chan<- string,
) {
	dec := &zipCryptoDecryptor{src: target.compData}
	fr := flate.NewReader(bytes.NewReader([]byte{0})) // dummy init
	resetter := fr.(flate.Resetter)
	crcW := crc32.NewIEEE()
	copyBuf := make([]byte, 32*1024)

	for task := range ch {
		if found.Load() {
			return
		}

		yy := task.year % 100
		mc := peselMonthCode(task.year, task.month)
		dd := [6]int{yy / 10, yy % 10, mc / 10, mc % 10, task.day / 10, task.day % 10}
		db := [6]byte{byte('0' + dd[0]), byte('0' + dd[1]), byte('0' + dd[2]), byte('0' + dd[3]), byte('0' + dd[4]), byte('0' + dd[5])}
		pk0, pk1, pk2 := zipCryptoPrecompute(db)
		partW := dd[0] + mul3[dd[1]] + mul7[dd[2]] + mul9[dd[3]] + dd[4] + mul3[dd[5]]

		for serial := 0; serial < 10000; serial++ {
			s3 := serial / 1000
			s2 := (serial / 100) % 10
			s1 := (serial / 10) % 10
			s0 := serial % 10

			wsum := partW + mul7[s3] + mul9[s2] + s1 + mul3[s0]
			cd := (10 - wsum%10) % 10

			sb := [5]byte{byte('0' + s3), byte('0' + s2), byte('0' + s1), byte('0' + s0), byte('0' + cd)}

			k0, k1, k2 := pk0, pk1, pk2
			for i := 0; i < 5; i++ {
				k0 = crc32Tab[(k0^uint32(sb[i]))&0xff] ^ (k0 >> 8)
				k1 = (k1 + (k0 & 0xff)) * 0x08088405 + 1
				k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
			}

			var last byte
			for i := 0; i < 12; i++ {
				temp := k2 | 2
				last = target.encHeader[i] ^ byte((temp*(temp^1))>>8)
				k0 = crc32Tab[(k0^uint32(last))&0xff] ^ (k0 >> 8)
				k1 = (k1 + (k0 & 0xff)) * 0x08088405 + 1
				k2 = crc32Tab[(k2^(k1>>24))&0xff] ^ (k2 >> 8)
			}

			if last != target.crcCheck && last != target.timeCheck {
				continue
			}

			// Header check passed — verify by decrypting+decompressing+CRC
			dec.reset(k0, k1, k2)
			resetter.Reset(dec, nil)
			crcW.Reset()

			_, err := io.CopyBuffer(crcW, fr, copyBuf)
			if err != nil {
				continue
			}
			if crcW.Sum32() != target.expectedCRC {
				continue
			}

			var pesel [11]byte
			copy(pesel[:6], db[:])
			copy(pesel[6:], sb[:])
			if found.CompareAndSwap(false, true) {
				resultCh <- string(pesel[:])
			}
			return
		}
		counter.Add(10000)
	}
}

func libWorker(
	zipData []byte,
	ch <-chan dateTask, found *atomic.Bool, counter *atomic.Int64, resultCh chan<- string,
) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return
	}
	var zf *zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() {
			zf = f
			break
		}
	}
	if zf == nil {
		return
	}
	probe := make([]byte, 128)

	for task := range ch {
		if found.Load() {
			return
		}

		yy := task.year % 100
		mc := peselMonthCode(task.year, task.month)
		dd := [6]int{yy / 10, yy % 10, mc / 10, mc % 10, task.day / 10, task.day % 10}
		partW := dd[0] + mul3[dd[1]] + mul7[dd[2]] + mul9[dd[3]] + dd[4] + mul3[dd[5]]

		var pesel [11]byte
		for i := 0; i < 6; i++ {
			pesel[i] = byte('0' + dd[i])
		}

		for serial := 0; serial < 10000; serial++ {
			s3 := serial / 1000
			s2 := (serial / 100) % 10
			s1 := (serial / 10) % 10
			s0 := serial % 10

			wsum := partW + mul7[s3] + mul9[s2] + s1 + mul3[s0]
			cd := (10 - wsum%10) % 10

			pesel[6] = byte('0' + s3)
			pesel[7] = byte('0' + s2)
			pesel[8] = byte('0' + s1)
			pesel[9] = byte('0' + s0)
			pesel[10] = byte('0' + cd)

			password := string(pesel[:])
			zf.SetPassword(password)
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			_, err = io.ReadFull(rc, probe)
			if err != nil {
				rc.Close()
				continue
			}
			_, err = io.Copy(io.Discard, rc)
			rc.Close()
			if err == nil {
				if found.CompareAndSwap(false, true) {
					resultCh <- password
				}
				return
			}
		}
		counter.Add(10000)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <zipfile>\n", os.Args[0])
		os.Exit(1)
	}

	zipData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid ZIP: %v\n", err)
		os.Exit(1)
	}
	if len(zr.File) == 0 {
		fmt.Fprintln(os.Stderr, "ZIP has no entries")
		os.Exit(1)
	}

	fmt.Printf("File:    %s (%d entries)\n", os.Args[1], len(zr.File))
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() {
			fmt.Printf("Entry:   %s (%d bytes)\n", f.Name, f.UncompressedSize64)
			break
		}
	}

	// Parse local file header for fast ZipCrypto path
	var target *zipTarget
	if len(zipData) >= 30 && binary.LittleEndian.Uint32(zipData[0:4]) == 0x04034b50 {
		flags := binary.LittleEndian.Uint16(zipData[6:8])
		method := binary.LittleEndian.Uint16(zipData[8:10])
		modTime := binary.LittleEndian.Uint16(zipData[10:12])
		fileCRC := binary.LittleEndian.Uint32(zipData[14:18])
		compSize := int(binary.LittleEndian.Uint32(zipData[18:22]))
		nameLen := int(binary.LittleEndian.Uint16(zipData[26:28]))
		extraLen := int(binary.LittleEndian.Uint16(zipData[28:30]))
		dataOff := 30 + nameLen + extraLen

		if flags&1 != 0 && method != 99 && compSize > 12 && len(zipData) >= dataOff+compSize {
			t := &zipTarget{
				crcCheck:    byte(fileCRC >> 24),
				timeCheck:   byte(modTime >> 8),
				compData:    zipData[dataOff+12 : dataOff+compSize],
				expectedCRC: fileCRC,
			}
			copy(t.encHeader[:], zipData[dataOff:dataOff+12])
			target = t
		}
	}

	numWorkers := runtime.NumCPU()
	mode := "library"
	if target != nil {
		mode = "ZipCrypto (fast)"
	}
	fmt.Printf("Mode:    %s\n", mode)
	fmt.Printf("Workers: %d\n", numWorkers)

	now := time.Now()
	totalDays := int(now.Sub(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)).Hours() / 24)
	fmt.Printf("Search:  ~%dM candidates (1900-%s, from 1977 outward)\n",
		totalDays/100, now.Format("2006-01-02"))

	var found atomic.Bool
	var counter atomic.Int64
	dateCh := make(chan dateTask, numWorkers*4)
	resultCh := make(chan string, 1)

	start := time.Now()

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if found.Load() {
				return
			}
			c := counter.Load()
			e := time.Since(start).Seconds()
			if e > 0.5 {
				fmt.Printf("\r  Checked: %dM | Speed: %.1fM/s | Elapsed: %.1fs        ",
					c/1_000_000, float64(c)/e/1_000_000, e)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if target != nil {
				fastWorker(target, dateCh, &found, &counter, resultCh)
			} else {
				libWorker(zipData, dateCh, &found, &counter, resultCh)
			}
		}()
	}

	go generateDates(dateCh, &found)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	password, ok := <-resultCh
	elapsed := time.Since(start)
	fmt.Println()
	if ok {
		fmt.Printf("\n*** PASSWORD FOUND: %s ***\n", password)
		fmt.Printf("Time: %s | Checked: %d\n", elapsed.Round(time.Millisecond), counter.Load())
	} else {
		fmt.Printf("\nPassword not found. Checked: %d | Time: %s\n",
			counter.Load(), elapsed.Round(time.Millisecond))
	}
}
