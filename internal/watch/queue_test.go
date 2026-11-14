package watch

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeQueue hands out the messages it is given, keeping those not
// acknowledged for redelivery, as a broker would.
type fakeQueue struct {
	mu      sync.Mutex
	pending []*fakeMessage
	acked   []string
	nacked  []string
}

type fakeMessage struct {
	q     *fakeQueue
	id    string
	body  string
	attrs map[string]string
	// onAck is called when the message is acknowledged.
	onAck func()
}

func (q *fakeQueue) send(m *fakeMessage) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m.q = q
	q.pending = append(q.pending, m)
}

func (q *fakeQueue) Receive(context.Context) ([]Message, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Message, len(q.pending))
	for i, m := range q.pending {
		out[i] = m
	}
	q.pending = nil
	return out, nil
}

func (m *fakeMessage) ID() string                    { return m.id }
func (m *fakeMessage) Body() []byte                  { return []byte(m.body) }
func (m *fakeMessage) Attributes() map[string]string { return m.attrs }
func (m *fakeMessage) Ack(context.Context) error {
	if m.onAck != nil {
		m.onAck()
	}
	m.q.mu.Lock()
	defer m.q.mu.Unlock()
	m.q.acked = append(m.q.acked, m.id)
	return nil
}

func (m *fakeMessage) Nack(context.Context) error {
	m.q.mu.Lock()
	defer m.q.mu.Unlock()
	m.q.nacked = append(m.q.nacked, m.id)
	return nil
}

func s3Event(bucket, key, etag string) string {
	return `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put",
		"s3":{"bucket":{"name":"` + bucket + `"},"object":{"key":"` + key + `","eTag":"` + etag + `"}}}]}`
}

func queueWatcher(t *testing.T, h *harness, q *fakeQueue) *Watcher {
	opts := h.options()
	opts.Buckets["s3"] = opts.Buckets["mem"]
	opts.Queues = map[string]QueueOpener{"fake": func(context.Context, *url.URL) (Queue, error) { return q, nil }}
	return openOne(t, h, WatcherConfig{Bucket: "s3://exports/drops/", Queue: "fake://q", Match: "*.jsonl"}, opts)
}

func TestQueueAcknowledgesOnceTheJobIsPersisted(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.put("drops/nightly users.jsonl", "users")
	q := &fakeQueue{}
	w := queueWatcher(t, h, q)

	id := JobID("test", "s3://exports/drops/nightly%20users.jsonl", "abc")
	persisted := false
	q.send(&fakeMessage{id: "m1", body: s3Event("exports", "drops/nightly+users.jsonl", "abc"), onAck: func() {
		_, err := h.runner.Store.Load(id)
		persisted = err == nil
	}})
	n, err := w.Poll(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.True(t, persisted, "the message is acknowledged only once its job is in the store")
	require.Equal(t, []string{"m1"}, q.acked)
	require.Len(t, h.jobs(), 1)

	// Redelivered (the ack was lost, say), even to a restarted server: no
	// second job, and acknowledged again.
	w = queueWatcher(t, h, q)
	q.send(&fakeMessage{id: "m1", body: s3Event("exports", "drops/nightly+users.jsonl", "abc")})
	_, err = w.Poll(ctx)
	require.NoError(t, err)
	require.Len(t, h.jobs(), 1)
	require.Equal(t, []string{"m1", "m1"}, q.acked)
	require.Equal(t, 0, w.Status().JobsCreated)
}

func TestQueueIgnoresOtherObjectsAndHandsBackFailures(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	q := &fakeQueue{}
	w := queueWatcher(t, h, q)

	q.send(&fakeMessage{id: "other-bucket", body: s3Event("another", "drops/u.jsonl", "1")})
	q.send(&fakeMessage{id: "other-prefix", body: s3Event("exports", "elsewhere/u.jsonl", "1")})
	q.send(&fakeMessage{id: "not-matched", body: s3Event("exports", "drops/u.csv", "1")})
	q.send(&fakeMessage{id: "test-event", body: `{"Service":"Amazon S3","Event":"s3:TestEvent"}`})
	q.send(&fakeMessage{id: "garbage", body: `hello`})
	q.send(&fakeMessage{id: "missing-object", body: s3Event("exports", "drops/gone.jsonl", "1")})
	h.put("drops/refuse.jsonl", "x")
	q.send(&fakeMessage{id: "refused", body: s3Event("exports", "drops/refuse.jsonl", "1")})
	_, err := w.Poll(ctx)
	require.NoError(t, err)

	require.Empty(t, h.jobs())
	require.Equal(t, []string{"other-bucket", "other-prefix", "not-matched", "test-event"}, q.acked)
	require.Equal(t, []string{"garbage", "missing-object", "refused"}, q.nacked,
		"a message no job could be persisted for is handed back, for the queue's dead-letter policy")
	require.Contains(t, w.Status().LastError, "message refused: refuse.jsonl: job params refused")
}

func TestParseNotification(t *testing.T) {
	for name, tc := range map[string]struct {
		body  string
		attrs map[string]string
		want  []objectEvent
	}{
		"s3 with version id": {
			body: `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:CompleteMultipartUpload","s3":{"bucket":{"name":"b"},"object":{"key":"a/b%2Bc.csv","eTag":"e","versionId":"v1"}}}]}`,
			want: []objectEvent{{Scheme: "s3", Bucket: "b", Key: "a/b+c.csv", Version: "v1"}},
		},
		"s3 deletion": {
			body: `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"b"},"object":{"key":"k"}}}]}`,
		},
		"s3 through sns": {
			body: `{"Type":"Notification","MessageId":"x","Message":"{\"Records\":[{\"eventSource\":\"aws:s3\",\"eventName\":\"ObjectCreated:Put\",\"s3\":{\"bucket\":{\"name\":\"b\"},\"object\":{\"key\":\"k\",\"eTag\":\"e\"}}}]}"}`,
			want: []objectEvent{{Scheme: "s3", Bucket: "b", Key: "k", Version: "e"}},
		},
		"gcs payload": {
			body:  `{"kind":"storage#object","bucket":"b","name":"p/k.csv","generation":"123"}`,
			attrs: map[string]string{"eventType": "OBJECT_FINALIZE"},
			want:  []objectEvent{{Scheme: "gs", Bucket: "b", Key: "p/k.csv", Version: "123"}},
		},
		"gcs attributes only": {
			attrs: map[string]string{"eventType": "OBJECT_FINALIZE", "bucketId": "b", "objectId": "k", "objectGeneration": "7"},
			want:  []objectEvent{{Scheme: "gs", Bucket: "b", Key: "k", Version: "7"}},
		},
		"gcs deletion": {
			body:  `{"kind":"storage#object","bucket":"b","name":"k","generation":"1"}`,
			attrs: map[string]string{"eventType": "OBJECT_DELETE", "bucketId": "b"},
		},
		"event grid schema": {
			body: `[{"eventType":"Microsoft.Storage.BlobCreated","subject":"/blobServices/default/containers/c/blobs/p/k.csv","data":{"eTag":"0x1"}},
				{"eventType":"Microsoft.Storage.BlobDeleted","subject":"/blobServices/default/containers/c/blobs/x"}]`,
			want: []objectEvent{{Scheme: "azblob", Bucket: "c", Key: "p/k.csv", Version: "0x1"}},
		},
		"cloudevents schema": {
			body: `{"specversion":"1.0","type":"Microsoft.Storage.BlobCreated","subject":"/blobServices/default/containers/c/blobs/k","data":{"eTag":"0x2"}}`,
			want: []objectEvent{{Scheme: "azblob", Bucket: "c", Key: "k", Version: "0x2"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseNotification([]byte(tc.body), tc.attrs)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	for _, body := range []string{`hello`, `{"foo":1}`, `[{"foo":1}]`} {
		_, err := parseNotification([]byte(body), nil)
		require.ErrorIs(t, err, errUnknownMessage, body)
	}
	_, err := parseNotification([]byte(`{"type":"Microsoft.Storage.BlobCreated","subject":"/nope"}`), nil)
	require.True(t, err != nil && strings.Contains(err.Error(), "doesn't name a blob"))
}
