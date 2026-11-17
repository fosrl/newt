package k8s

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// labelPrefix is the prefix of the Docker-style labels the Pangolin server
	// understands (e.g. pangolin.public-resources.web.full-domain).
	labelPrefix = "pangolin."

	// annotationDomainPrefix is the qualified-name prefix that can be used on
	// Service annotations (e.g. pangolin.net/public-resources.web.full-domain).
	// It exists because the name part of a Kubernetes annotation key is limited
	// to 63 characters, which long resource keys can exceed when written as
	// pangolin.<...> in the bare form.
	annotationDomainPrefix = "pangolin.net/"

	// blueprintAnnotation holds a YAML blueprint snippet for the Service.
	blueprintAnnotation = annotationDomainPrefix + "blueprint"
)

// resourceSections are the top level blueprint sections the server reads from
// container labels.
var resourceSections = map[string]bool{
	"proxy-resources":   true,
	"client-resources":  true,
	"public-resources":  true,
	"private-resources": true,
}

// HasPangolinAnnotations reports whether any annotation is a Pangolin one.
func HasPangolinAnnotations(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, labelPrefix) || strings.HasPrefix(k, annotationDomainPrefix) {
			return true
		}
	}
	return false
}

// AnnotationsToLabels converts Service annotations into the Docker-style label
// map that the Pangolin server parses.
//
// Two forms are supported and can be mixed (individual annotations win over the
// YAML blueprint on conflict):
//
//   - Individual annotations, either pangolin.<section>.<key>.<path> or
//     pangolin.net/<section>.<key>.<path>. Kubernetes does not allow '[' or ']'
//     in annotation keys, so array indexes are written as dotted numbers
//     (targets.0.port) and rewritten to targets[0].port here.
//   - A pangolin.net/blueprint annotation containing a YAML snippet with the
//     same structure as a blueprint file.
//
// Annotations that are not Pangolin annotations are ignored. Problems with
// individual annotations are returned as warnings and do not abort conversion.
func AnnotationsToLabels(annotations map[string]string) (labels map[string]string, warnings []error) {
	labels = make(map[string]string)

	if raw, ok := annotations[blueprintAnnotation]; ok {
		if err := blueprintToLabels(raw, labels); err != nil {
			warnings = append(warnings, fmt.Errorf("annotation %s: %w", blueprintAnnotation, err))
		}
	}

	keys := make([]string, 0, len(annotations))
	for k := range annotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if key == blueprintAnnotation {
			continue
		}

		var rest string
		switch {
		case strings.HasPrefix(key, annotationDomainPrefix):
			rest = strings.TrimPrefix(key, annotationDomainPrefix)
		case strings.HasPrefix(key, labelPrefix):
			rest = strings.TrimPrefix(key, labelPrefix)
		default:
			continue
		}

		label, err := normalizeKey(rest)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("annotation %s: %w", key, err))
			continue
		}
		labels[label] = annotations[key]
	}

	return labels, warnings
}

// normalizeKey turns "<section>.<key>.<path>" (dotted indexes) into the full
// "pangolin.<section>.<key>.<path>" label with bracketed indexes.
func normalizeKey(rest string) (string, error) {
	segments := strings.Split(rest, ".")
	if len(segments) < 3 || !resourceSections[segments[0]] {
		return "", fmt.Errorf("expected <section>.<resource>.<property> where section is one of proxy-resources, client-resources, public-resources or private-resources")
	}

	// segments[0] is the section and segments[1] the resource key. A numeric
	// resource key is a name, not an index, so only rewrite from the property
	// path onwards. The property path cannot start with an index.
	if isIndex(segments[2]) {
		return "", fmt.Errorf("property name cannot be a number")
	}
	out := []string{segments[0], segments[1], segments[2]}
	for _, seg := range segments[3:] {
		if isIndex(seg) {
			out[len(out)-1] += "[" + seg + "]"
			continue
		}
		out = append(out, seg)
	}

	return labelPrefix + strings.Join(out, "."), nil
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// blueprintToLabels flattens a YAML blueprint snippet into labels.
func blueprintToLabels(raw string, labels map[string]string) error {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	var firstErr error
	for section, v := range doc {
		if !resourceSections[section] {
			if firstErr == nil {
				firstErr = fmt.Errorf("unsupported top level key %q", section)
			}
			continue
		}
		resources, ok := v.(map[string]interface{})
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("%q must be a map of resources", section)
			}
			continue
		}
		for resourceKey, cfg := range resources {
			flatten(labelPrefix+section+"."+resourceKey, cfg, labels)
		}
	}
	return firstErr
}

// flatten writes the leaves of v into out using dotted keys and [N] indexes.
func flatten(prefix string, v interface{}, out map[string]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			flatten(prefix+"."+k, child, out)
		}
	case []interface{}:
		for i, child := range t {
			flatten(prefix+"["+strconv.Itoa(i)+"]", child, out)
		}
	case nil:
		// nothing to set
	case string:
		out[prefix] = t
	default:
		out[prefix] = fmt.Sprint(t)
	}
}
