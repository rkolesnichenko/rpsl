package nrtm4_test

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/nrtm4"
	"github.com/rkolesnichenko/rpsl/types"
)

// ExampleClient keeps a mirror of the RIPE Database current and expands an
// as-set against it. The key is the one RIPE publishes at
// https://ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt; after a
// rotation, Status().CurrentKey is the one to keep.
func ExampleClient() {
	key, err := os.ReadFile("ripe-nrtmv4-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	c := &nrtm4.Client{
		URL:       "https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose",
		Database:  "RIPE",
		PublicKey: string(key),
	}
	ctx := context.Background()
	if _, err := c.Sync(ctx); err != nil { // the snapshot, then the deltas since
		log.Fatal(err)
	}
	go c.Run(ctx, time.Minute, func(err error) { log.Print(err) })

	// Each Source is one version, whole: take one per expansion.
	e := &resolve.Expander{Src: c.Source()}
	name, _ := types.ParseSetName("AS-RIPENCC")
	prefixes, err := e.ExpandPrefixes(ctx, types.Ref(name))
	if err != nil {
		log.Fatal(err)
	}
	log.Print(prefixes.List())
}
