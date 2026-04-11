package network

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"vertesan/hailstorm/manifest"
	"vertesan/hailstorm/rich"
)

const LOGIN_URL = "https://api.link-like-lovelive.app/v1/user/login"

var letterRunes = []rune("abcdef0123456789")

func Login(clientVersion string, platform string) string {
	buf := bytes.NewBufferString(`{"device_specific_id":"","player_id":"","version":1}`)
	req, err := http.NewRequest("POST", LOGIN_URL, buf)
	if err != nil {
		panic(err)
	}
	platform = manifest.NormalizePlatform(platform)
	// prepare headers
	idempotencyId := RandStringRunes(32)
	// looks like header.set has a bug, every first alphabet followed by "-" must be
	// upper-cased or the Set method will take no effect.
	header := loginHeader.Clone()
	header.Set("X-Idempotency-Key", idempotencyId)
	header.Set("X-Client-Version", clientVersion)
	header.Set("User-Agent", fmt.Sprintf("inspix-%s/%v", platform, clientVersion))
	header.Set("x-device-type", platform)

	req.Header = header

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		rich.Panic("Login failed. Status: %v.", res.Status)
	}

	resInfo := res.Header.Get("x-res-version")
	res.Body.Close()
	rich.Info("Login succeeded for platform %q. Res info: %q.", platform, resInfo)
	return resInfo
}

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
