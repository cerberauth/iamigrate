package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cerberauth/iamigrate/internal/jobs"
)

// Client talks to a running `iamigrate serve`.
type Client struct {
	// BaseURL is the server's address, e.g. http://127.0.0.1:8080.
	BaseURL string
	// Token is sent as the bearer token if set.
	Token string
	// HTTPClient is http.DefaultClient if nil.
	HTTPClient *http.Client
}

// Error is an error response from the server.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("server answered %d: %s", e.Status, e.Message)
}

// Create queues a job, which the server starts running at once.
func (c *Client) Create(ctx context.Context, params map[string]string) (*jobs.Job, error) {
	var j jobs.Job
	if err := c.do(ctx, http.MethodPost, "/jobs", CreateRequest{Params: params}, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Get returns the job record.
func (c *Client) Get(ctx context.Context, id string) (*jobs.Job, error) {
	var j jobs.Job
	if err := c.do(ctx, http.MethodGet, "/jobs/"+url.PathEscape(id), nil, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Report returns what a finished job's steps found. The server answers 409
// while the job is still running.
func (c *Client) Report(ctx context.Context, id string) (*Report, error) {
	var r Report
	if err := c.do(ctx, http.MethodGet, "/jobs/"+url.PathEscape(id)+"/report", nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Retry puts a failed job back in the state from, or the one it failed in if
// from is empty, and has the server run it again.
func (c *Client) Retry(ctx context.Context, id string, from jobs.State) (*jobs.Job, error) {
	var j jobs.Job
	if err := c.do(ctx, http.MethodPost, "/jobs/"+url.PathEscape(id)+"/retry", RetryRequest{From: from}, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

// Wait polls the job every interval until it reaches a terminal state,
// calling onPoll, if set, with each record it reads.
func (c *Client) Wait(ctx context.Context, id string, interval time.Duration, onPoll func(*jobs.Job)) (*jobs.Job, error) {
	for {
		j, err := c.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if onPoll != nil {
			onPoll(j)
		}
		if j.State.Terminal() {
			return j, nil
		}
		select {
		case <-ctx.Done():
			return j, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var e ErrorResponse
		if json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
