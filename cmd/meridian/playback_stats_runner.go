package main

import (
	"context"
	"log"
	"time"
)

const playbackFlushInterval = 2 * time.Minute
const playbackPruneInterval = 6 * time.Hour

// runPlaybackCounter flushes buffered playback counts and prunes old buckets.
// Counts live in memory between flushes so a burst of playbacks costs one write.
func runPlaybackCounter(ctx context.Context, counter *playbackCounter, db *DB) {
	if counter == nil || db == nil {
		return
	}
	flushTicker := time.NewTicker(playbackFlushInterval)
	defer flushTicker.Stop()
	pruneTicker := time.NewTicker(playbackPruneInterval)
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := counter.flush(db); err != nil {
				log.Printf("[playback-stats] final flush failed: %v", err)
			}
			return
		case <-flushTicker.C:
			if err := counter.flush(db); err != nil {
				log.Printf("[playback-stats] flush failed: %v", err)
			}
		case <-pruneTicker.C:
			if err := db.prunePlaybackEvents(time.Now()); err != nil {
				log.Printf("[playback-stats] retention prune failed: %v", err)
			}
		}
	}
}
