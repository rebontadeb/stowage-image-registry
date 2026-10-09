package service

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// retyped is a layer that reports a different media type. Its bytes, digest and diff ID are unchanged.
type retyped struct {
	v1.Layer
	mt types.MediaType
}

func (r retyped) MediaType() (types.MediaType, error) { return r.mt, nil }

// layerTypeFor maps a layer's media type to the one a manifest of the given format expects. A manifest must not
// mix the two families: registries such as quay, and copy tools that recompress, reject an OCI manifest that
// holds a Docker layer type (and the other way round).
func layerTypeFor(layer, manifest types.MediaType) types.MediaType {
	oci := manifest == types.OCIManifestSchema1
	switch {
	case oci && layer == types.DockerLayer:
		return types.OCILayer
	case !oci && layer == types.OCILayer:
		return types.DockerLayer
	}
	return layer // zstd, foreign and other special layers are left alone
}

// alignMediaTypes rebuilds img with the manifest and config media types of the image it was made from, and every
// layer of the matching family. The content is not changed.
func alignMediaTypes(img v1.Image, manifest, config types.MediaType) (v1.Image, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	var add []mutate.Addendum
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		if want := layerTypeFor(mt, manifest); want != mt {
			l = retyped{Layer: l, mt: want}
		}
		add = append(add, mutate.Addendum{Layer: l})
	}
	out := mutate.MediaType(empty.Image, manifest)
	out = mutate.ConfigMediaType(out, config)
	if len(add) > 0 {
		if out, err = mutate.Append(out, add...); err != nil {
			return nil, err
		}
	}
	return mutate.ConfigFile(out, cfg) // same layers, so the diff IDs in cfg still match
}

// formatOf returns the manifest and config media types of an image.
func formatOf(img v1.Image) (manifest, config types.MediaType, err error) {
	if manifest, err = img.MediaType(); err != nil {
		return
	}
	m, err := img.Manifest()
	if err != nil {
		return
	}
	return manifest, m.Config.MediaType, nil
}
