// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package preview

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, s := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(s))
	}
	zw.Close()
	return buf.Bytes()
}

func pdf(content string) []byte {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(content))
	zw.Close()
	return []byte("%PDF-1.4\n1 0 obj\n<< /Length " + "10" + " /Filter /FlateDecode >>\nstream\n" + z.String() + "\nendstream\nendobj\n%%EOF")
}

func TestPreview(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		kind string
		want string
	}{
		{"notes.txt", []byte("Quarterly numbers\nare up."), KindText, "Quarterly numbers\nare up."},
		{"page.html", []byte("<p>Hello <b>there</b></p><script>alert(1)</script>"), KindText, "Hello there"},
		{"report.docx", zipOf(t, map[string]string{"[Content_Types].xml": "<x/>", "word/document.xml": `<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Budget</w:t></w:r><w:r><w:tab/><w:t>2027</w:t></w:r></w:p><w:p><w:r><w:t>Second line</w:t></w:r></w:p></w:body></w:document>`}), KindText, "Budget\t2027\nSecond line"},
		{"sheet.xlsx", zipOf(t, map[string]string{"xl/workbook.xml": "<x/>", "xl/sharedStrings.xml": `<sst><si><t>Name</t></si><si><t>Total</t></si></sst>`, "xl/worksheets/sheet1.xml": `<worksheet><sheetData><row><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row><row><c t="inlineStr"><is><t>Ana</t></is></c><c><v>42</v></c></row></sheetData></worksheet>`}), KindText, "— Sheet 1 —\nName\tTotal\nAna\t42"},
		{"deck.pptx", zipOf(t, map[string]string{"ppt/presentation.xml": "<x/>", "ppt/slides/slide2.xml": `<p:sld><a:p><a:r><a:t>Second</a:t></a:r></a:p></p:sld>`, "ppt/slides/slide1.xml": `<p:sld><a:p><a:r><a:t>First</a:t></a:r></a:p></p:sld>`}), KindText, "— Slide 1 —\nFirst\n\n— Slide 2 —\nSecond"},
		{"files.zip", zipOf(t, map[string]string{"a.txt": "hi", "setup.exe": "MZ"}), KindList, ""},
		{"memo.rtf", []byte(`{\rtf1\ansi{\fonttbl{\f0 Arial;}}\f0 Hello\par World \'e9t\'e9}`), KindText, "Hello\nWorld été"},
		{"invoice.pdf", pdf("BT /F1 12 Tf 72 700 Td (Invoice 4471) Tj 0 -14 Td [(Total: ) -20 (\\(EUR\\) 120)] TJ ET"), KindText, "Invoice 4471\nTotal: (EUR) 120"},
		{"scan.pdf", pdf("q 100 0 0 100 0 0 cm /Im1 Do Q"), KindNone, ""},
		{"blob.bin", []byte{0, 1, 2, 3, 0xff}, KindNone, ""},
	}
	for _, c := range cases {
		r := Of(c.name, "", bytes.NewReader(c.body))
		if r.Kind != c.kind || c.want != "" && r.Text != c.want {
			t.Errorf("%s: %s %q (%s)", c.name, r.Kind, r.Text, r.Note)
		}
	}
	r := Of("files.zip", "", bytes.NewReader(cases[5].body))
	if len(r.Items) != 2 || r.SHA256 == "" {
		t.Fatalf("%+v", r)
	}
	if m := Of("macro.docx", "", bytes.NewReader(zipOf(t, map[string]string{"word/document.xml": "<w:t>x</w:t>", "word/vbaProject.bin": "x"}))); !strings.Contains(m.Note, "macros") {
		t.Fatal("macro note")
	}
}

func TestImageRedraw(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var src bytes.Buffer
	jpeg.Encode(&src, img, nil)
	src.WriteString("PK\x03\x04 hidden zip appended to the image")
	if r := Of("photo.jpg", "image/jpeg", bytes.NewReader(src.Bytes())); r.Kind != KindImage {
		t.Fatalf("%+v", r)
	}
	var out bytes.Buffer
	if err := Image(bytes.NewReader(src.Bytes()), &out); err != nil {
		t.Fatal(err)
	}
	got, err := png.Decode(bytes.NewReader(out.Bytes()))
	if err != nil || got.Bounds().Dx() != 4 || bytes.Contains(out.Bytes(), []byte("hidden zip")) {
		t.Fatalf("redraw: %v", err)
	}
	// A huge declared size is refused before decoding.
	var bomb bytes.Buffer
	png.Encode(&bomb, image.NewGray(image.Rect(0, 0, 1, 1)))
	b := bomb.Bytes()
	b[16], b[17], b[18], b[19] = 0, 1, 0, 0 // width 65536
	b[20], b[21], b[22], b[23] = 0, 1, 0, 0 // height 65536
	if err := Image(bytes.NewReader(b), &out); err == nil {
		t.Fatal("image bomb decoded")
	}
	if !Risky("a.docm", "") || !Risky("x.pdf", "application/pdf") || Risky("photo.jpg", "image/jpeg") {
		t.Fatal("Risky")
	}
}
