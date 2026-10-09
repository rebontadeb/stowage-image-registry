package service

import (
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestRebaseOntoSwapsBaseLayersAndKeepsTheApp(t *testing.T) {
	oldBase, _ := random.Image(256, 2)
	newBase, _ := random.Image(256, 3)
	appLayer, _ := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	orig, err := mutate.Append(oldBase, mutate.Addendum{Layer: appLayer, History: v1.History{CreatedBy: "COPY app"}})
	if err != nil {
		t.Fatal(err)
	}
	oc, _ := orig.ConfigFile()
	oc = oc.DeepCopy()
	oc.Config.User, oc.Config.Cmd = "app", []string{"/run"}
	if orig, err = mutate.ConfigFile(orig, oc); err != nil {
		t.Fatal(err)
	}

	got, err := rebaseOnto(orig, oldBase, newBase, 0)
	if err != nil {
		t.Fatal(err)
	}
	gc, _ := got.ConfigFile()
	nc, _ := newBase.ConfigFile()
	ac, _ := appLayer.DiffID()
	want := append(append([]v1.Hash{}, nc.RootFS.DiffIDs...), ac)
	if len(gc.RootFS.DiffIDs) != len(want) {
		t.Fatalf("layers = %d, want %d", len(gc.RootFS.DiffIDs), len(want))
	}
	for i := range want {
		if gc.RootFS.DiffIDs[i] != want[i] {
			t.Errorf("layer %d is %s, want %s", i, gc.RootFS.DiffIDs[i], want[i])
		}
	}
	if gc.Config.User != "app" || len(gc.Config.Cmd) != 1 || gc.Config.Cmd[0] != "/run" {
		t.Errorf("the image's own configuration must be kept: %+v", gc.Config)
	}
	if last := gc.History[len(gc.History)-1]; last.CreatedBy != "COPY app" {
		t.Errorf("application history lost: %+v", gc.History)
	}
}

func TestRebaseOntoRefusesAnImageNotBuiltOnTheOldBase(t *testing.T) {
	a, _ := random.Image(256, 2)
	b, _ := random.Image(256, 2)
	n, _ := random.Image(256, 2)
	if _, err := rebaseOnto(a, b, n, 0); !errors.Is(err, errNotOnBase) {
		t.Fatalf("want errNotOnBase, got %v", err)
	}
	empty, _ := mutate.Config(a, v1.Config{}) // same layers: a base with all of the image's layers is fine, an unrelated one is not
	if _, err := rebaseOnto(empty, a, n, 0); err != nil {
		t.Fatalf("an image identical to its base can be rebased: %v", err)
	}
}

func TestRebaseOntoByLayerCountIgnoresAMovedBaseTag(t *testing.T) {
	rebuilt, _ := random.Image(256, 2) // the old base's tag now points at different layers
	oldBase, _ := random.Image(256, 2)
	newBase, _ := random.Image(256, 3)
	appLayer, _ := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	orig, _ := mutate.Append(oldBase, mutate.Addendum{Layer: appLayer})
	if _, err := rebaseOnto(orig, rebuilt, newBase, 0); !errors.Is(err, errNotOnBase) {
		t.Fatalf("the rebuilt tag must not match by content, got %v", err)
	}
	got, err := rebaseOnto(orig, nil, newBase, 2)
	if err != nil {
		t.Fatal(err)
	}
	if gc, _ := got.ConfigFile(); len(gc.RootFS.DiffIDs) != 4 {
		t.Fatalf("want 3 base layers + 1 app layer, got %d", len(gc.RootFS.DiffIDs))
	}
	if _, err := rebaseOnto(orig, nil, newBase, 3); err == nil {
		t.Fatal("the whole image cannot be the base")
	}
}
