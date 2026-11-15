package canon

import "testing"

func TestSortsKeys(t *testing.T) {
	got, err := JSON([]byte(`{"b":1,"a":"x","c":[true,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"x","b":1,"c":[true,null]}`
	if string(got) != want {
		t.Fatalf("got %s", got)
	}
}

func TestStable(t *testing.T) {
	a, err := JSON([]byte(`{"z":1,"m":{"b":2,"a":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := JSON(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("not stable\n%s\n%s", a, b)
	}
}

func TestStringEscape(t *testing.T) {
	got, err := JSON([]byte(`{"s":"a\"b\\c\n中"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"s\":\"a\\\"b\\\\c\\n中\"}"
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
