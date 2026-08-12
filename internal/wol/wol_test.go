package wol

import (
	"bytes"
	"net"
	"testing"
)

func TestPacketFormat(t *testing.T) {
	hw, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	pkt, err := Packet(hw)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 102 {
		t.Fatalf("packet length = %d, want 102", len(pkt))
	}
	if !bytes.Equal(pkt[:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("packet must start with 6 bytes of 0xFF")
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(pkt[6+i*6:6+(i+1)*6], hw) {
			t.Fatalf("MAC repetition %d is wrong", i)
		}
	}
}

func TestPacketRejectsNon6ByteMAC(t *testing.T) {
	// A valid EUI-64 parses to 8 bytes — a magic packet needs exactly 6.
	hw, err := net.ParseMAC("02:00:5e:10:00:00:00:01")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Packet(hw); err == nil {
		t.Error("8-byte MAC should be rejected")
	}
}

func TestWakeRejectsGarbage(t *testing.T) {
	if err := Wake("not-a-mac"); err == nil {
		t.Error("garbage MAC should error")
	}
}
