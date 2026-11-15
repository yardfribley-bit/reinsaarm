package main

import (
	"io"
	"os"
)

func osStderr() io.Writer { return os.Stderr }
