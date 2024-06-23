{{- /*
mychart.shortname provides a 6 char truncated version of the release name.
*/ -}}
{{- define "dctm-cmis.release-labels" }}
app: {{ .Release.Name }}-{{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
version: {{ .Chart.Version }}
release: {{ .Release.Name }}
{{- end }}

{{- define "dctm-cmis.custom-labels" }}
{{- range $key, $val := .Values.customLabels }}
{{ $key }}: {{ $val }}
{{- end}}
{{- end }}

{{- define "dctm-cmis.fullname" -}}
{{ .Release.Name }}-{{ .Chart.Name }}
{{- end }}