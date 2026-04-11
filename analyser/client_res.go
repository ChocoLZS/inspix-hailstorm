package analyser

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"vertesan/hailstorm/crypto"
	"vertesan/hailstorm/manifest"
	"vertesan/hailstorm/rich"
	"vertesan/hailstorm/utils"
)

var (
	resHeaderPtn = regexp.MustCompile(`R\d+@[A-Za-z0-9+/=]+`)
)

type ClientResEntry struct {
	RawValue     string `json:"rawValue"`
	ResHeader    string `json:"resHeader"`
	SimpleResver string `json:"simpleResver"`
	Checksum     uint64 `json:"checksum"`
	ChecksumHex  string `json:"checksumHex"`
	Seed         uint64 `json:"seed"`
	SeedHex      string `json:"seedHex"`
	Size         uint64 `json:"size"`
	SizeVlqHex   string `json:"sizeVlqHex"`
	LabelCrc     uint64 `json:"labelCrc"`
	LabelCrcHex  string `json:"labelCrcHex"`
	RealName     string `json:"realName"`
	PayloadHex   string `json:"payloadHex"`
	WasSanitized bool   `json:"wasSanitized"`
}

type ClientResVersionReport struct {
	ClientVersion string           `json:"clientVersion"`
	Entries       []ClientResEntry `json:"entries"`
}

type SharedSimpleResver struct {
	SimpleResver  string   `json:"simpleResver"`
	Versions      []string `json:"versions"`
	Headers       []string `json:"headers"`
	ChecksumCount int      `json:"checksumCount"`
	SeedCount     int      `json:"seedCount"`
	SizeCount     int      `json:"sizeCount"`
	RealNameCount int      `json:"realNameCount"`
}

type ClientResSummary struct {
	VersionCount         int                  `json:"versionCount"`
	HeaderCount          int                  `json:"headerCount"`
	UniqueSimpleResver   int                  `json:"uniqueSimpleResver"`
	UniqueRealName       int                  `json:"uniqueRealName"`
	SanitizedHeaderCount int                  `json:"sanitizedHeaderCount"`
	ReusedSimpleResvers  []SharedSimpleResver `json:"reusedSimpleResvers"`
}

type clientResAccumulator struct {
	versions  map[string]struct{}
	headers   map[string]struct{}
	checksums map[uint64]struct{}
	seeds     map[uint64]struct{}
	sizes     map[uint64]struct{}
	realNames map[string]struct{}
}

func AnalyzeClientRes(src string, reportDst string, summaryDst string) {
	raw := map[string][]string{}
	if err := utils.ReadFromJsonFile(src, &raw); err != nil {
		panic(err)
	}

	versions := make([]string, 0, len(raw))
	for version := range raw {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i int, j int) bool {
		return compareVersion(versions[i], versions[j]) > 0
	})

	reports := make([]ClientResVersionReport, 0, len(versions))
	reused := make(map[string]*clientResAccumulator)
	uniqueRealNames := make(map[string]struct{})
	totalHeaders := 0
	sanitizedHeaders := 0

	for _, version := range versions {
		versionReport := ClientResVersionReport{
			ClientVersion: version,
			Entries:       []ClientResEntry{},
		}
		for _, rawValue := range raw[version] {
			cleanValue := sanitizeResHeader(rawValue)
			if cleanValue == "" {
				rich.Warning("Skipping unparsable res header in %q: %q", version, rawValue)
				continue
			}
			if cleanValue != rawValue {
				sanitizedHeaders++
			}
			entry := parseClientResEntry(rawValue, cleanValue)
			versionReport.Entries = append(versionReport.Entries, entry)
			totalHeaders++
			uniqueRealNames[entry.RealName] = struct{}{}

			acc, ok := reused[entry.SimpleResver]
			if !ok {
				acc = &clientResAccumulator{
					versions:  make(map[string]struct{}),
					headers:   make(map[string]struct{}),
					checksums: make(map[uint64]struct{}),
					seeds:     make(map[uint64]struct{}),
					sizes:     make(map[uint64]struct{}),
					realNames: make(map[string]struct{}),
				}
				reused[entry.SimpleResver] = acc
			}
			acc.versions[version] = struct{}{}
			acc.headers[entry.ResHeader] = struct{}{}
			acc.checksums[entry.Checksum] = struct{}{}
			acc.seeds[entry.Seed] = struct{}{}
			acc.sizes[entry.Size] = struct{}{}
			acc.realNames[entry.RealName] = struct{}{}
		}
		reports = append(reports, versionReport)
	}

	summary := ClientResSummary{
		VersionCount:         len(reports),
		HeaderCount:          totalHeaders,
		UniqueSimpleResver:   len(reused),
		UniqueRealName:       len(uniqueRealNames),
		SanitizedHeaderCount: sanitizedHeaders,
	}
	for simpleResver, acc := range reused {
		if len(acc.headers) <= 1 {
			continue
		}
		summary.ReusedSimpleResvers = append(summary.ReusedSimpleResvers, SharedSimpleResver{
			SimpleResver:  simpleResver,
			Versions:      sortedStrings(acc.versions),
			Headers:       sortedStrings(acc.headers),
			ChecksumCount: len(acc.checksums),
			SeedCount:     len(acc.seeds),
			SizeCount:     len(acc.sizes),
			RealNameCount: len(acc.realNames),
		})
	}
	sort.Slice(summary.ReusedSimpleResvers, func(i int, j int) bool {
		left := summary.ReusedSimpleResvers[i]
		right := summary.ReusedSimpleResvers[j]
		if left.RealNameCount != right.RealNameCount {
			return left.RealNameCount > right.RealNameCount
		}
		return left.SimpleResver > right.SimpleResver
	})

	if err := os.MkdirAll(filepathDir(reportDst), 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepathDir(summaryDst), 0755); err != nil {
		panic(err)
	}

	utils.WriteToJsonFile(reports, reportDst)
	utils.WriteToJsonFile(summary, strings.TrimSuffix(summaryDst, ".md")+".json")
	if err := os.WriteFile(summaryDst, []byte(renderClientResSummary(summary)), 0644); err != nil {
		panic(err)
	}
	detailDst := strings.TrimSuffix(summaryDst, ".md") + "_detail.md"
	if err := os.WriteFile(detailDst, []byte(renderClientResDetail(reports)), 0644); err != nil {
		panic(err)
	}
	rich.Info("Client res report written to %q and %q.", reportDst, summaryDst)
}

func parseClientResEntry(rawValue string, resHeader string) ClientResEntry {
	parts := strings.SplitN(resHeader, "@", 2)
	if len(parts) != 2 {
		panic(fmt.Sprintf("invalid res header: %q", resHeader))
	}
	payload := utils.Must(base64.StdEncoding.DecodeString(parts[1]))
	reader := bytes.NewReader(payload)

	var checksum uint64
	var seed uint64
	if err := binary.Read(reader, binary.BigEndian, &checksum); err != nil {
		panic(err)
	}
	if err := binary.Read(reader, binary.BigEndian, &seed); err != nil {
		panic(err)
	}
	size, err := binary.ReadUvarint(reader)
	if err != nil {
		panic(err)
	}

	vlqBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(vlqBuf, size)
	labelCrc := crypto.UpdateCrc64(0, []byte(parts[0]), len(parts[0]), nil)

	return ClientResEntry{
		RawValue:     rawValue,
		ResHeader:    resHeader,
		SimpleResver: parts[0],
		Checksum:     checksum,
		ChecksumHex:  fmt.Sprintf("%016X", checksum),
		Seed:         seed,
		SeedHex:      fmt.Sprintf("%016X", seed),
		Size:         size,
		SizeVlqHex:   strings.ToUpper(hex.EncodeToString(vlqBuf[:n])),
		LabelCrc:     labelCrc,
		LabelCrcHex:  fmt.Sprintf("%016X", labelCrc),
		RealName:     manifest.GetRealName(checksum, labelCrc, size),
		PayloadHex:   strings.ToUpper(hex.EncodeToString(payload)),
		WasSanitized: rawValue != resHeader,
	}
}

func sanitizeResHeader(raw string) string {
	return resHeaderPtn.FindString(raw)
}

func compareVersion(left string, right string) int {
	lParts := parseVersion(left)
	rParts := parseVersion(right)
	maxLen := len(lParts)
	if len(rParts) > maxLen {
		maxLen = len(rParts)
	}
	for i := 0; i < maxLen; i++ {
		lVal := 0
		rVal := 0
		if i < len(lParts) {
			lVal = lParts[i]
		}
		if i < len(rParts) {
			rVal = rParts[i]
		}
		if lVal > rVal {
			return 1
		}
		if lVal < rVal {
			return -1
		}
	}
	return 0
}

func parseVersion(version string) []int {
	parts := strings.Split(version, ".")
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		values = append(values, utils.Must(strconv.Atoi(part)))
	}
	return values
}

func sortedStrings[M ~map[string]struct{}](set M) []string {
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items
}

func filepathDir(path string) string {
	idx := strings.LastIndexAny(path, `/\`)
	if idx == -1 {
		return "."
	}
	return path[:idx]
}

func renderClientResSummary(summary ClientResSummary) string {
	var sb strings.Builder
	sb.WriteString("# client-res summary\n\n")
	sb.WriteString(fmt.Sprintf("- versions: %d\n", summary.VersionCount))
	sb.WriteString(fmt.Sprintf("- headers: %d\n", summary.HeaderCount))
	sb.WriteString(fmt.Sprintf("- unique simpleResver: %d\n", summary.UniqueSimpleResver))
	sb.WriteString(fmt.Sprintf("- unique realname: %d\n", summary.UniqueRealName))
	sb.WriteString(fmt.Sprintf("- sanitized headers: %d\n", summary.SanitizedHeaderCount))
	sb.WriteString("\n## observed invariants\n\n")
	sb.WriteString("- `labelcrc = CRC64(simpleResver)` using the repo's custom ECMA-182-style table implementation.\n")
	sb.WriteString("- `realname = base32(md5(checksum || labelcrc || VLQ(size)))`.\n")
	sb.WriteString("- `checksum`, `seed`, and `size` are carried directly in the base64 payload after `@`.\n")
	sb.WriteString("- `simpleResver` reuse does happen, so `realname` is not determined by `simpleResver` alone.\n")

	if len(summary.ReusedSimpleResvers) == 0 {
		return sb.String()
	}

	sb.WriteString("\n## reused simpleResver\n\n")
	for _, item := range summary.ReusedSimpleResvers {
		sb.WriteString(fmt.Sprintf("- `%s`: versions=%s, headers=%d, checksum=%d, seed=%d, size=%d, realname=%d\n",
			item.SimpleResver,
			strings.Join(item.Versions, ", "),
			len(item.Headers),
			item.ChecksumCount,
			item.SeedCount,
			item.SizeCount,
			item.RealNameCount,
		))
	}
	return sb.String()
}

func renderClientResDetail(reports []ClientResVersionReport) string {
	var sb strings.Builder
	sb.WriteString("# client-res detail\n\n")
	sb.WriteString("## decode rule\n\n")
	sb.WriteString("- payload after `@` = `checksum(8-byte BE) || seed(8-byte BE) || size(UVarint)`\n")
	sb.WriteString("- `labelcrc = CRC64(simpleResver)`\n")
	sb.WriteString("- `realname = base32(md5(checksum || labelcrc || VLQ(size)))`\n")
	sb.WriteString("- `seed` does not participate in `realname` generation\n")

	for _, version := range reports {
		sb.WriteString("\n")
		sb.WriteString("## ")
		sb.WriteString(version.ClientVersion)
		sb.WriteString("\n\n")
		if len(version.Entries) == 0 {
			sb.WriteString("_empty_\n")
			continue
		}
		sb.WriteString("| simpleResver | checksum | seed | size | labelcrc | realname |\n")
		sb.WriteString("| --- | --- | --- | ---: | --- | --- |\n")
		for _, entry := range version.Entries {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%d` | `%s` | `%s` |\n",
				entry.SimpleResver,
				entry.ChecksumHex,
				entry.SeedHex,
				entry.Size,
				entry.LabelCrcHex,
				entry.RealName,
			))
		}
	}

	type reusedRow struct {
		SimpleResver string
		Entries      []ClientResEntry
		Versions     []string
	}

	var reused []reusedRow
	bySimple := make(map[string]reusedRow)
	for _, version := range reports {
		for _, entry := range version.Entries {
			row := bySimple[entry.SimpleResver]
			row.SimpleResver = entry.SimpleResver
			row.Entries = append(row.Entries, entry)
			row.Versions = append(row.Versions, version.ClientVersion)
			bySimple[entry.SimpleResver] = row
		}
	}
	for _, row := range bySimple {
		if len(row.Entries) > 1 {
			reused = append(reused, row)
		}
	}
	sort.Slice(reused, func(i int, j int) bool {
		if len(reused[i].Entries) != len(reused[j].Entries) {
			return len(reused[i].Entries) > len(reused[j].Entries)
		}
		return reused[i].SimpleResver > reused[j].SimpleResver
	})

	sb.WriteString("\n## reused simpleResver detail\n\n")
	for _, row := range reused {
		sb.WriteString("### ")
		sb.WriteString(row.SimpleResver)
		sb.WriteString("\n\n")
		sb.WriteString("| clientVersion | checksum | seed | size | labelcrc | realname |\n")
		sb.WriteString("| --- | --- | --- | ---: | --- | --- |\n")
		for idx, entry := range row.Entries {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%d` | `%s` | `%s` |\n",
				row.Versions[idx],
				entry.ChecksumHex,
				entry.SeedHex,
				entry.Size,
				entry.LabelCrcHex,
				entry.RealName,
			))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
