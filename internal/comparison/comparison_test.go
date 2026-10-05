package comparison_test

import (
	"testing"

	"github.com/meneeses/cloudthreat-atlas/internal/comparison"
	"github.com/meneeses/cloudthreat-atlas/internal/model"
)

func TestCompareIsDirectionalAndDeterministic(t *testing.T) {
	base := model.Snapshot{ID: "base", RiskScore: 20, Resources: []model.ResourceNode{{ID: "b"}, {ID: "a"}}, Findings: []model.Finding{{ID: "old"}}}
	target := model.Snapshot{ID: "target", RiskScore: 45, Resources: []model.ResourceNode{{ID: "c"}, {ID: "b"}}, Findings: []model.Finding{{ID: "new"}}}
	result := comparison.Compare(base, target)
	if result.RiskScoreDelta != 25 || len(result.Resources.Added) != 1 || result.Resources.Added[0] != "c" || result.Resources.Removed[0] != "a" {
		t.Fatalf("comparison = %+v", result)
	}
	if result.Findings.Added[0] != "new" || result.Findings.Removed[0] != "old" {
		t.Fatalf("finding changes = %+v", result.Findings)
	}
}
