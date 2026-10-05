package atlas_test

import (
	"fmt"

	atlas "github.com/meneeses/cloudthreat-atlas"
)

func ExampleSnapshot() {
	snapshot := atlas.Snapshot{
		SchemaVersion: "1.0",
		ID:            "example",
		Name:          "Example environment",
		Provider:      "azure",
	}

	fmt.Printf("%s: %s", snapshot.Provider, snapshot.Name)
	// Output: azure: Example environment
}
