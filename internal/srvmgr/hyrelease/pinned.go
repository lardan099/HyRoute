package hyrelease

// pinned are the SHA-256 of the Linux binaries of versions HyRoute knows,
// copied from each release's hashes.txt: a replaced release file does not
// pass for the real one.
var pinned = map[string]map[string]string{
	"v2.12.3": {
		"hysteria-linux-386":       "5e4178a112cc13e7fabf09ce29a98b9dca586dbbf78bb5ada121f9ce056a4e3c",
		"hysteria-linux-amd64":     "8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e",
		"hysteria-linux-arm":       "cc4bc596c2db473dd7ec1bbcc3cd10e0cb60302759facd95e0be73bc8751e110",
		"hysteria-linux-arm64":     "c8dc653c3ba0a28d29a26b8fa52d2086f27c0927afddce95c09965e7174e78b0",
		"hysteria-linux-armv5":     "385a3938636a5ca4e5706fc8508b8279fdbda93514fbba199e24fcaefb65ce6e",
		"hysteria-linux-loong64":   "dbd5c9396d574dbb792040e15c0da582aee90507ce9cb4f1347392fb976ecb91",
		"hysteria-linux-mipsle":    "d9d1682068f2aac632b03a8d41c6ae5799f079c576a04ba3b0ca3c32a21ff142",
		"hysteria-linux-mipsle-sf": "ebfbe51582766de197d4b941722d6674c37024c1025a565fa6600e98ca598f6f",
		"hysteria-linux-riscv64":   "06e1a17dd88936fc126d1b83b8ed51ad3a4815f2b4ca325bd2139af86344e392",
		"hysteria-linux-s390x":     "54b12020936503c010d4083cddd577a6b1bb1885e14e4ef49f2dee83723a14b9",
	},
}
