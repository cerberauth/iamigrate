package importprep

// SetBatchForTest sets how many users a's Reader prepares at a time.
func SetBatchForTest(a *Applier, n int) { a.batch = n }
