package watch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// objectEvent is an object created in a bucket, as an event notification
// tells it.
type objectEvent struct {
	// Scheme is the bucket URI scheme of the provider: s3, gs or azblob.
	Scheme  string
	Bucket  string
	Key     string
	Version string
}

// errUnknownMessage is returned for a message that isn't a bucket event
// notification parseNotification knows.
var errUnknownMessage = errors.New("not a bucket event notification (Amazon S3, Google Cloud Storage or Azure Event Grid)")

// parseNotification returns the objects created that a queue message
// notifies of: none for a notification of anything else (a deletion, a
// test event). It reads:
//   - Amazon S3 event notifications, as sent to SQS directly or through
//     an SNS topic;
//   - Google Cloud Storage Pub/Sub notifications (JSON_API_V1 payload, or
//     no payload and the object in the attributes);
//   - Azure Blob Storage events from Event Grid, in the Event Grid or
//     CloudEvents schema, one event or an array.
func parseNotification(body []byte, attrs map[string]string) ([]objectEvent, error) {
	// Google Cloud Storage: the event type and the object are attributes.
	if t, ok := attrs["eventType"]; ok && attrs["bucketId"] != "" {
		if t != "OBJECT_FINALIZE" {
			return nil, nil
		}
		return []objectEvent{{Scheme: "gs", Bucket: attrs["bucketId"], Key: attrs["objectId"], Version: attrs["objectGeneration"]}}, nil
	}

	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		var events []json.RawMessage
		if err := json.Unmarshal(body, &events); err != nil {
			return nil, err
		}
		var out []objectEvent
		for _, e := range events {
			ev, err := parseAzureEvent(e)
			if err != nil {
				return nil, err
			}
			out = append(out, ev...)
		}
		return out, nil
	}

	var probe struct {
		Records   json.RawMessage `json:"Records"`
		Event     string          `json:"Event"`
		Type      string          `json:"Type"`
		Message   string          `json:"Message"`
		Kind      string          `json:"kind"`
		EventType string          `json:"eventType"`
		CEType    string          `json:"type"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, errUnknownMessage
	}
	switch {
	case probe.Records != nil:
		return parseS3Records(probe.Records)
	case probe.Event == "s3:TestEvent":
		return nil, nil
	case probe.Type == "Notification" && probe.Message != "":
		// SNS wraps the S3 notification in its own envelope.
		return parseNotification([]byte(probe.Message), nil)
	case probe.Kind == "storage#object":
		var o struct {
			Bucket     string `json:"bucket"`
			Name       string `json:"name"`
			Generation string `json:"generation"`
		}
		if err := json.Unmarshal(body, &o); err != nil {
			return nil, err
		}
		return []objectEvent{{Scheme: "gs", Bucket: o.Bucket, Key: o.Name, Version: o.Generation}}, nil
	case strings.HasPrefix(probe.EventType, "Microsoft.") || strings.HasPrefix(probe.CEType, "Microsoft."):
		return parseAzureEvent(body)
	}
	return nil, errUnknownMessage
}

func parseS3Records(raw json.RawMessage) ([]objectEvent, error) {
	var records []struct {
		EventSource string `json:"eventSource"`
		EventName   string `json:"eventName"`
		S3          struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key       string `json:"key"`
				ETag      string `json:"eTag"`
				VersionID string `json:"versionId"`
			} `json:"object"`
		} `json:"s3"`
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("decoding S3 event records: %w", err)
	}
	var out []objectEvent
	for _, r := range records {
		if r.EventSource != "aws:s3" || !strings.HasPrefix(r.EventName, "ObjectCreated:") {
			continue
		}
		// Keys are URL-encoded, with '+' for a space.
		key, err := url.QueryUnescape(r.S3.Object.Key)
		if err != nil {
			return nil, fmt.Errorf("S3 event key %q: %w", r.S3.Object.Key, err)
		}
		version := r.S3.Object.VersionID
		if version == "" {
			version = r.S3.Object.ETag
		}
		out = append(out, objectEvent{Scheme: "s3", Bucket: r.S3.Bucket.Name, Key: key, Version: version})
	}
	return out, nil
}

// parseAzureEvent reads an Event Grid event in the Event Grid schema
// (eventType) or the CloudEvents one (type).
func parseAzureEvent(raw json.RawMessage) ([]objectEvent, error) {
	var e struct {
		EventType string `json:"eventType"`
		Type      string `json:"type"`
		Subject   string `json:"subject"`
		Data      struct {
			ETag string `json:"eTag"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("decoding an Event Grid event: %w", err)
	}
	if e.EventType != "Microsoft.Storage.BlobCreated" && e.Type != "Microsoft.Storage.BlobCreated" {
		if e.EventType == "" && e.Type == "" {
			return nil, errUnknownMessage
		}
		return nil, nil
	}
	// /blobServices/default/containers/<container>/blobs/<key>
	rest, ok := strings.CutPrefix(e.Subject, "/blobServices/default/containers/")
	container, key, ok2 := strings.Cut(rest, "/blobs/")
	if !ok || !ok2 || container == "" || key == "" {
		return nil, fmt.Errorf("event grid: subject %q doesn't name a blob", e.Subject)
	}
	return []objectEvent{{Scheme: "azblob", Bucket: container, Key: key, Version: e.Data.ETag}}, nil
}
