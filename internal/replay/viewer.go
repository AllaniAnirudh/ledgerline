package replay

import _ "embed"

//go:embed viewer.html
var viewerHTML []byte

// ViewerHTML returns the replay timeline page served at /replay.
// It is dependency-free HTML+JS that reads the gateway's own API.
func ViewerHTML() []byte { return viewerHTML }
