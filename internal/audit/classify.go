package audit

import (
	"path/filepath"
	"strings"
)

var extCategory = map[string]string{
	".dds": "textures", ".tif": "textures", ".png": "textures",
	".wav": "audio", ".ogg": "audio", ".wem": "audio", ".bnk": "audio",
	".bik": "video", ".usm": "video",
	".lua": "scripts",
	".cfx": "shaders", ".cfi": "shaders", ".cfm": "shaders",
	".caf": "animations", ".chr": "animations", ".skin": "animations",
	".cgf": "geometry", ".cga": "geometry",
}

func Classify(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if cat, ok := extCategory[ext]; ok {
		return cat
	}
	return "other"
}
