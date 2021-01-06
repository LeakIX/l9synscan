package l9synscan_test

import (
	"github.com/LeakIX/l9synscan"
	"testing"
)

func TestParsePortsList(t *testing.T) {
	ports, err := l9synscan.ParsePortsList("1,2,3")
	if err != nil {
		t.Log("error should be nil", err)
		t.Fail()
	}
	if len(ports) != 3 {
		t.Log("port count should be 3 is", len(ports))
		t.Fail()
	}
	ports, err = l9synscan.ParsePortsList("1-20,2,3")
	if err != nil {
		t.Log("error should be nil", err)
		t.Fail()
	}
	if len(ports) != 20 {
		t.Log("port count should be 3, is", len(ports))
		t.Fail()
	}
	ports, err = l9synscan.ParsePortsList("1-ew20,2,3")
	if err == nil {
		t.Log("error should be returned for incorrect port list")
		t.Fail()
	}
}
