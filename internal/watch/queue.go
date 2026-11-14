package watch

import (
	"context"
	"net/url"
)

// Queue is a message queue a watcher consumes a bucket's event
// notifications from. Its provider registers it by URI scheme (see
// Options.Queues).
type Queue interface {
	// Receive waits for messages, for as long as the provider's long poll
	// lasts or until ctx is done, and returns those that arrived, possibly
	// none. A message not acknowledged is redelivered later.
	Receive(ctx context.Context) ([]Message, error)
}

// Message is a message received from a Queue.
type Message interface {
	// ID is the message's ID, stable across redeliveries.
	ID() string
	// Body is the message's payload.
	Body() []byte
	// Attributes are the message's attributes (or headers), if the
	// transport has them.
	Attributes() map[string]string
	// Ack removes the message from the queue: it was handled.
	Ack(ctx context.Context) error
	// Nack hands the message back for redelivery, or to the queue's
	// dead-letter queue once it has failed often enough.
	Nack(ctx context.Context) error
}

// QueueOpener opens the Queue a URI names.
type QueueOpener func(ctx context.Context, u *url.URL) (Queue, error)
