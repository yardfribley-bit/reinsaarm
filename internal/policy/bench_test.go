package policy

import "testing"

func BenchmarkEvaluate(b *testing.B) {
	p, err := Load(DefaultYAML())
	if err != nil {
		b.Fatal(err)
	}
	e := Compile(p, "/home/dev", DefaultYAML())
	actions := benchActions()
	ctx := Context{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(actions[i%len(actions)], ctx)
	}
}
