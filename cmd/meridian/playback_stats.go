package main

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Playback counts are derived from PlaybackInfo requests: Emby clients issue
// exactly one when the user starts (or re-starts) a playback session, which is a
// far better "someone pressed play" signal than raw media byte counts.
const (
	playbackEventBucketMinutes = 60
	playbackEventRetentionDays = 90
)

type playbackCounter struct {
	pending sync.Map // key -> *atomic.Int64
	flushMu sync.Mutex
}

type playbackKey struct {
	siteID int64
	bucket time.Time
}

func newPlaybackCounter() *playbackCounter { return &playbackCounter{} }

// recordPlaybackStart increments the in-memory counter for the current hour.
// Flushing is batched so a busy evening does not turn into one SQLite write per
// playback.
func (c *playbackCounter) recordPlaybackStart(siteID int64, when time.Time) {
	if c == nil || siteID <= 0 {
		return
	}
	bucket := when.UTC().Truncate(playbackEventBucketMinutes * time.Minute)
	key := playbackKey{siteID: siteID, bucket: bucket}
	counter, _ := c.pending.LoadOrStore(key, new(atomic.Int64))
	counter.(*atomic.Int64).Add(1)
}

// flush writes accumulated counts to the database and clears the pending map.
func (c *playbackCounter) flush(d *DB) error {
	if c == nil || d == nil {
		return nil
	}
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	var batch []playbackKey
	var counts []int64
	c.pending.Range(func(k, v any) bool {
		n := v.(*atomic.Int64).Swap(0)
		if n > 0 {
			batch = append(batch, k.(playbackKey))
			counts = append(counts, n)
		}
		return true
	})
	if len(batch) == 0 {
		return nil
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO playback_events (site_id, bucket_at, plays) VALUES (?,?,?)
		ON CONFLICT(site_id, bucket_at) DO UPDATE SET plays = plays + excluded.plays`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, key := range batch {
		if _, err := stmt.Exec(key.siteID, key.bucket.Format(time.RFC3339), counts[i]); err != nil {
			// Restore the count so a transient failure does not lose playbacks.
			existing, _ := c.pending.LoadOrStore(key, new(atomic.Int64))
			existing.(*atomic.Int64).Add(counts[i])
			continue
		}
		c.pending.Delete(key)
	}
	return tx.Commit()
}

// prunePlaybackEvents drops buckets older than the retention window.
func (d *DB) prunePlaybackEvents(now time.Time) error {
	if d == nil {
		return nil
	}
	cutoff := now.UTC().AddDate(0, 0, -playbackEventRetentionDays)
	_, err := d.db.Exec(`DELETE FROM playback_events WHERE bucket_at < ?`, cutoff.Format(time.RFC3339))
	return err
}

// PlaybackPoint is one bucket in the trend response.
type PlaybackPoint struct {
	At    string `json:"at"`
	Plays int64  `json:"plays"`
}

// PlaybackSeries is the per-site playback trend returned to the dashboard.
type PlaybackSeries struct {
	SiteID   int64           `json:"site_id"`
	SiteName string          `json:"site_name"`
	Range    string          `json:"range"`
	Total    int64           `json:"total"`
	Today    int64           `json:"today"`
	Points   []PlaybackPoint `json:"points"`
}

type playbackSiteTotal struct {
	SiteID   int64  `json:"site_id"`
	SiteName string `json:"site_name"`
	Plays    int64  `json:"plays"`
}

func playbackRangeStart(rangeName string, now time.Time) (time.Time, time.Duration) {
	switch strings.ToLower(strings.TrimSpace(rangeName)) {
	case "24h":
		return now.Add(-24 * time.Hour).Truncate(playbackEventBucketMinutes * time.Minute), playbackEventBucketMinutes * time.Minute
	case "30d":
		return now.AddDate(0, 0, -30).Truncate(24 * time.Hour), 24 * time.Hour
	default: // 7d
		return now.AddDate(0, 0, -7).Truncate(24 * time.Hour), 24 * time.Hour
	}
}

// playbackSeries aggregates the stored buckets into a fixed-size series so the
// chart always has one point per interval, including empty intervals.
func (d *DB) playbackSeries(siteID int64, rangeName string, now time.Time) (PlaybackSeries, error) {
	start, step := playbackRangeStart(rangeName, now)
	series := PlaybackSeries{SiteID: siteID, Range: strings.ToLower(strings.TrimSpace(rangeName))}
	if series.Range == "" {
		series.Range = "7d"
	}
	query := `SELECT site_id, bucket_at, plays FROM playback_events WHERE bucket_at >= ?`
	args := []any{start.Format(time.RFC3339)}
	if siteID > 0 {
		query += ` AND site_id = ?`
		args = append(args, siteID)
	}
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return series, err
	}
	defer rows.Close()
	buckets := map[time.Time]int64{}
	for rows.Next() {
		var id int64
		var raw string
		var plays int64
		if err := rows.Scan(&id, &raw, &plays); err != nil {
			return series, err
		}
		at, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			continue
		}
		buckets[at] = buckets[at] + plays
	}
	if err := rows.Err(); err != nil {
		return series, err
	}
	todayStart := now.UTC().Truncate(24 * time.Hour)
	for at := start; !at.After(now); at = at.Add(step) {
		plays := buckets[at]
		series.Points = append(series.Points, PlaybackPoint{At: at.Format(time.RFC3339), Plays: plays})
		series.Total += plays
		if !at.Before(todayStart) {
			series.Today += plays
		}
	}
	if siteID > 0 {
		var name string
		if err := d.db.QueryRow(`SELECT name FROM sites WHERE id=?`, siteID).Scan(&name); err == nil {
			series.SiteName = name
		}
	}
	return series, nil
}

// playbackTotalsBySite ranks sites by playbacks inside the range.
func (d *DB) playbackTotalsBySite(rangeName string, now time.Time) ([]playbackSiteTotal, error) {
	start, _ := playbackRangeStart(rangeName, now)
	rows, err := d.db.Query(`SELECT p.site_id, COALESCE(s.name,''), SUM(p.plays)
		FROM playback_events p LEFT JOIN sites s ON s.id = p.site_id
		WHERE p.bucket_at >= ? GROUP BY p.site_id ORDER BY SUM(p.plays) DESC`, start.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []playbackSiteTotal
	for rows.Next() {
		var row playbackSiteTotal
		if err := rows.Scan(&row.SiteID, &row.SiteName, &row.Plays); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// GET /api/playback-stats?range=7d|24h|30d&site_id=all|<id>
func (a *App) handlePlaybackStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	now := time.Now()
	var siteID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("site_id")); raw != "" && !strings.EqualFold(raw, "all") {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			a.jsonErr(w, http.StatusBadRequest, "invalid site id")
			return
		}
		if _, err := a.db.GetSite(id); err != nil {
			a.jsonErr(w, http.StatusNotFound, "site not found")
			return
		}
		siteID = id
	}
	series, err := a.db.playbackSeries(siteID, r.URL.Query().Get("range"), now)
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "failed to read playback stats")
		return
	}
	totals, err := a.db.playbackTotalsBySite(r.URL.Query().Get("range"), now)
	if err != nil {
		a.jsonErr(w, http.StatusInternalServerError, "failed to read playback stats")
		return
	}
	a.jsonOK(w, map[string]any{"series": series, "by_site": totals})
}
