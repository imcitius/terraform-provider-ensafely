package provider

import (
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// checkJSON is the flat check payload of /api/check-definitions (CheckWrite
// and CheckRead in docs/api/openapi.yaml). Only the fields of the check types
// this provider manages are listed; unknown response fields are ignored.
//
// Zero values are omitted, so an unset Terraform attribute and an empty API
// value are the same thing. PUT replaces every editable field, so the
// provider always sends the complete configuration. Secret fields are
// pointers: nil keeps the stored secret (secret contract), a pointer to an
// empty value clears it. ConnectionID is a pointer for the same reason: the
// API keeps the stored reference when it is omitted, so the provider always
// sends it, "" for none.
type checkJSON struct {
	UUID        string `json:"uuid,omitempty"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Project     string `json:"project"`
	GroupName   string `json:"group_name,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Duration    string `json:"duration,omitempty"`

	Severity             string   `json:"severity,omitempty"`
	AlertChannels        []string `json:"alert_channels,omitempty"`
	ReAlertInterval      string   `json:"re_alert_interval,omitempty"`
	RetryCount           int      `json:"retry_count,omitempty"`
	RetryInterval        string   `json:"retry_interval,omitempty"`
	EscalationPolicyName string   `json:"escalation_policy_name,omitempty"`
	RunMode              string   `json:"run_mode,omitempty"`
	TargetRegions        []string `json:"target_regions,omitempty"`
	EdgeMinUnhealthy     int      `json:"edge_min_unhealthy,omitempty"`

	URL                 string               `json:"url,omitempty"`
	Timeout             string               `json:"timeout,omitempty"`
	Host                string               `json:"host,omitempty"`
	Port                int                  `json:"port,omitempty"`
	Answer              string               `json:"answer,omitempty"`
	AnswerPresent       bool                 `json:"answer_present,omitempty"`
	Code                []int                `json:"code,omitempty"`
	Headers             *[]map[string]string `json:"headers,omitempty"`
	SkipCheckSSL        bool                 `json:"skip_check_ssl,omitempty"`
	SSLExpirationPeriod string               `json:"ssl_expiration_period,omitempty"`
	StopFollowRedirects bool                 `json:"stop_follow_redirects,omitempty"`
	Auth                *checkAuthJSON       `json:"auth,omitempty"`
	Count               int                  `json:"count,omitempty"`
	Domain              string               `json:"domain,omitempty"`
	ExpiryWarningDays   int                  `json:"expiry_warning_days,omitempty"`
	RecordType          string               `json:"record_type,omitempty"`
	Expected            string               `json:"expected,omitempty"`
	ValidateChain       bool                 `json:"validate_chain,omitempty"`
	ExpectBanner        string               `json:"expect_banner,omitempty"`
	RedisPassword       *string              `json:"redis_password,omitempty"`
	RedisDB             int                  `json:"redis_db,omitempty"`
	StartTLS            bool                 `json:"starttls,omitempty"`
	SMTPUsername        string               `json:"smtp_username,omitempty"`
	SMTPPassword        *string              `json:"smtp_password,omitempty"`
	UseTLS              bool                 `json:"use_tls,omitempty"`
	MongoDBURI          *string              `json:"mongodb_uri,omitempty"`
	MySQL               *checkDBJSON         `json:"mysql,omitempty"`
	PgSQL               *checkDBJSON         `json:"pgsql,omitempty"`

	ConnectionID *string `json:"connection_id,omitempty"`
}

// checkDBJSON is the nested mysql or pgsql object. sslmode is PostgreSQL
// only. Replication and time-query fields are not managed (#115 covers the
// pgsql_query and mysql_query types).
type checkDBJSON struct {
	Username string  `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
	DBName   string  `json:"dbname,omitempty"`
	SSLMode  string  `json:"sslmode,omitempty"`
	Query    string  `json:"query,omitempty"`
	Response string  `json:"response,omitempty"`
}

type checkAuthJSON struct {
	User     string  `json:"user,omitempty"`
	Password *string `json:"password,omitempty"`
}

func (j *checkJSON) auth() *checkAuthJSON {
	if j.Auth == nil {
		j.Auth = &checkAuthJSON{}
	}
	return j.Auth
}

func (j *checkJSON) mysql() *checkDBJSON {
	if j.MySQL == nil {
		j.MySQL = &checkDBJSON{}
	}
	return j.MySQL
}

func (j *checkJSON) pgsql() *checkDBJSON {
	if j.PgSQL == nil {
		j.PgSQL = &checkDBJSON{}
	}
	return j.PgSQL
}

// fieldKind is the Terraform type of a mapped field.
type fieldKind int

const (
	kindString fieldKind = iota
	kindInt
	kindBool
	kindIntSet
	kindStringSet
)

func (k fieldKind) attrType() attr.Type {
	switch k {
	case kindInt:
		return types.Int64Type
	case kindBool:
		return types.BoolType
	case kindIntSet:
		return types.SetType{ElemType: types.Int64Type}
	case kindStringSet:
		return types.SetType{ElemType: types.StringType}
	default:
		return types.StringType
	}
}

// checkField maps one Terraform attribute to one API field. The table of
// fields drives the resource schema, the data source schema and both
// directions of the JSON mapping, so they cannot drift apart.
//
// The API omits zero values, so a zero value maps to null. To keep that
// mapping lossless, schemas reject explicit zero values (empty strings,
// empty sets, 0 where the API treats 0 as unset). Booleans have a false
// default instead.
type checkField struct {
	name, desc string
	kind       fieldKind
	required   bool
	// duration validates a Go duration string such as 30s or 1m.
	duration bool
	oneOf    []string
	// minInt/maxInt bound integers; minInt is at least 1 because 0 is unset.
	minInt, maxInt int64
	// fromConnection marks a required field that a Connection supplies
	// instead: it is required only without connection_id.
	fromConnection bool
	// credential marks a field that conflicts with connection_id, because
	// the Connection provides it.
	credential bool
	// url rejects a URL with a userinfo password: the API masks it on read,
	// which would cause drift.
	url bool
	// ptr returns a pointer to the API field: *string, *int, *bool, *[]int
	// or *[]string according to kind.
	ptr func(*checkJSON) any
}

// checkSecret is a write-only secret exposed as <name>_wo plus
// <name>_wo_version.
type checkSecret struct {
	name, desc string
	// isMap selects a map of strings instead of a string.
	isMap bool
	// required makes <name>_wo required without connection_id.
	required bool
	// credential: conflicts with connection_id, and is cleared on the
	// server whenever connection_id is set, so no stale inline credential
	// outlives the switch to a Connection.
	credential bool
	// set stores the secret in the request; nil value means "clear".
	set func(j *checkJSON, value attr.Value)
}

// checkType is one polymorphic type block.
type checkType struct {
	block   string // Terraform block name
	apiType string // API "type" discriminator
	desc    string
	// connection is the ensafely_connection type whose credentials the
	// server applies to this check type; empty means connection_id is not
	// supported.
	connection string
	fields     []checkField
	secrets    []checkSecret
}

func (t checkType) attrTypes(withSecrets bool) map[string]attr.Type {
	m := make(map[string]attr.Type, len(t.fields)+2*len(t.secrets))
	for _, f := range t.fields {
		m[f.name] = f.kind.attrType()
	}
	if withSecrets {
		for _, s := range t.secrets {
			m[s.name+"_wo"] = types.StringType
			if s.isMap {
				m[s.name+"_wo"] = types.MapType{ElemType: types.StringType}
			}
			m[s.name+"_wo_version"] = types.Int64Type
		}
	}
	return m
}

func strField(name, desc string, ptr func(*checkJSON) *string) checkField {
	return checkField{name: name, desc: desc, kind: kindString, ptr: func(j *checkJSON) any { return ptr(j) }}
}

func intField(name, desc string, minInt, maxInt int64, ptr func(*checkJSON) *int) checkField {
	return checkField{name: name, desc: desc, kind: kindInt, minInt: minInt, maxInt: maxInt, ptr: func(j *checkJSON) any { return ptr(j) }}
}

func boolField(name, desc string, ptr func(*checkJSON) *bool) checkField {
	return checkField{name: name, desc: desc, kind: kindBool, ptr: func(j *checkJSON) any { return ptr(j) }}
}

func (f checkField) req() checkField           { f.required = true; return f }
func (f checkField) dur() checkField           { f.duration = true; return f }
func (f checkField) of(v ...string) checkField { f.oneOf = v; return f }

// reqUnlessConnection makes the field required without connection_id.
func (f checkField) reqUnlessConnection() checkField {
	f.required, f.fromConnection = true, true
	return f
}

// cred marks a credential that conflicts with connection_id.
func (f checkField) cred() checkField { f.credential = true; return f }

func (f checkField) noURLPassword() checkField { f.url = true; return f }

// stringSecret is a write-only string secret stored through field.
func stringSecret(name, desc string, field func(*checkJSON) **string) checkSecret {
	return checkSecret{name: name, desc: desc, set: func(j *checkJSON, v attr.Value) {
		s := ""
		if v != nil {
			s = v.(types.String).ValueString()
		}
		*field(j) = &s
	}}
}

func (s checkSecret) cred() checkSecret { s.credential = true; return s }

func (s checkSecret) reqUnlessConnection() checkSecret { s.required = true; return s }

func portField(def string) checkField {
	return intField("port", "Port. Omit for "+def+".", 1, 65535, func(j *checkJSON) *int { return &j.Port })
}

// databaseType is pgsql_query or mysql_query: the same fields in the nested
// pgsql or mysql object.
func databaseType(block, name, connection, defaultPort string, db func(*checkJSON) *checkDBJSON, sslMode bool) checkType {
	fields := []checkField{
		hostField("Database server host name or address. Required unless `connection_id` is set.").reqUnlessConnection(),
		portField(defaultPort),
		strField("username", "Database user. Conflicts with `connection_id`.",
			func(j *checkJSON) *string { return &db(j).Username }).cred(),
		strField("db_name", "Database name.", func(j *checkJSON) *string { return &db(j).DBName }),
	}
	if sslMode {
		fields = append(fields, strField("ssl_mode", "PostgreSQL `sslmode`, for example `require`. Omit for the Probe default.",
			func(j *checkJSON) *string { return &db(j).SSLMode }))
	}
	fields = append(fields,
		strField("query", "Query to run; the check reads the first column of the first row. Omit for `SELECT 1`.",
			func(j *checkJSON) *string { return &db(j).Query }),
		strField("response", "Value the query must return. Omit to accept any result.",
			func(j *checkJSON) *string { return &db(j).Response }),
		timeoutField(),
	)
	return checkType{
		block: block, apiType: block, connection: connection,
		desc:   name + " query check: connects, runs `query` and optionally compares the result with `response`.",
		fields: fields,
		secrets: []checkSecret{
			stringSecret("password", "Database password. Conflicts with `connection_id`.",
				func(j *checkJSON) **string { return &db(j).Password }).cred(),
		},
	}
}

const durationHint = " A Go duration such as `30s`, `5m` or `1h`."

func timeoutField() checkField {
	return strField("timeout", "Per-attempt timeout. Omit for the type default."+durationHint,
		func(j *checkJSON) *string { return &j.Timeout }).dur()
}

var hostField = func(desc string) checkField {
	return strField("host", desc, func(j *checkJSON) *string { return &j.Host })
}

var expiryWarningDaysField = intField("expiry_warning_days", "Days before expiry at which the check fails. Omit for the default.", 1, 0,
	func(j *checkJSON) *int { return &j.ExpiryWarningDays })

// checkTypes lists the type blocks this provider version manages (#114,
// #115). The replication and time-query variants of the database types
// (mysql_query_unixtime, mysql_replication, pgsql_query_unixtime,
// pgsql_query_timestamp, pgsql_replication, pgsql_replication_status) are not
// managed.
var checkTypes = []checkType{
	{
		block: "http", apiType: "http", connection: "http",
		desc: "HTTP(S) request check.",
		fields: []checkField{
			strField("url", "URL to request. Required unless `connection_id` is set (the Connection's `base_url` is then used). "+
				"Put credentials in `basic_auth_user` and `basic_auth_password_wo`, not in the URL.",
				func(j *checkJSON) *string { return &j.URL }).reqUnlessConnection().noURLPassword(),
			timeoutField(),
			strField("answer", "Text the response body must contain (or must not contain, see `answer_present`).",
				func(j *checkJSON) *string { return &j.Answer }),
			boolField("answer_present", "Check that `answer` is present in the body. Defaults to `false`.",
				func(j *checkJSON) *bool { return &j.AnswerPresent }),
			{name: "status_codes", desc: "Accepted HTTP status codes. Omit to accept 200.", kind: kindIntSet, minInt: 100, maxInt: 599,
				ptr: func(j *checkJSON) any { return &j.Code }},
			boolField("skip_check_ssl", "Skip TLS certificate verification. Defaults to `false`.",
				func(j *checkJSON) *bool { return &j.SkipCheckSSL }),
			strField("ssl_expiration_period", "Fail when the TLS certificate expires within this period, for example `720h`.",
				func(j *checkJSON) *string { return &j.SSLExpirationPeriod }).dur(),
			boolField("stop_follow_redirects", "Do not follow redirects. Defaults to `false`.",
				func(j *checkJSON) *bool { return &j.StopFollowRedirects }),
			strField("basic_auth_user", "HTTP basic authentication user name. Conflicts with `connection_id`.",
				func(j *checkJSON) *string { return &j.auth().User }).cred(),
		},
		secrets: []checkSecret{
			stringSecret("basic_auth_password", "HTTP basic authentication password. Conflicts with `connection_id`.",
				func(j *checkJSON) **string { return &j.auth().Password }).cred(),
			{
				name: "headers", desc: "Request headers (name → value). All header values are treated as secrets.", isMap: true,
				set: func(j *checkJSON, v attr.Value) {
					headers := []map[string]string{}
					if v != nil {
						elems := v.(types.Map).Elements()
						names := make([]string, 0, len(elems))
						for name := range elems {
							names = append(names, name)
						}
						sort.Strings(names)
						for _, name := range names {
							headers = append(headers, map[string]string{name: elems[name].(types.String).ValueString()})
						}
					}
					j.Headers = &headers
				},
			},
		},
	},
	{
		block: "tcp", apiType: "tcp",
		desc: "TCP connect check.",
		fields: []checkField{
			hostField("Host name or IP address.").req(),
			intField("port", "TCP port.", 1, 65535, func(j *checkJSON) *int { return &j.Port }).req(),
			timeoutField(),
		},
	},
	{
		block: "icmp", apiType: "icmp",
		desc: "ICMP ping check.",
		fields: []checkField{
			hostField("Host name or IP address.").req(),
			intField("count", "Number of echo requests. Omit for the default.", 1, 0, func(j *checkJSON) *int { return &j.Count }),
			timeoutField(),
		},
	},
	{
		block: "dns", apiType: "dns",
		desc: "DNS lookup check.",
		fields: []checkField{
			strField("domain", "Name to look up.", func(j *checkJSON) *string { return &j.Domain }).req(),
			strField("record_type", "Record type. Omit for `A`.", func(j *checkJSON) *string { return &j.RecordType }).
				of("A", "AAAA", "MX", "TXT", "NS", "CNAME"),
			strField("expected", "Value that must appear in the answer.", func(j *checkJSON) *string { return &j.Expected }),
			hostField("DNS resolver to query, for example `1.1.1.1:53`. Omit for the Probe's resolver."),
			timeoutField(),
		},
	},
	{
		block: "ssl_cert", apiType: "ssl_cert",
		desc: "TLS certificate expiry and validity check.",
		fields: []checkField{
			hostField("Host name.").req(),
			intField("port", "TLS port. Omit for 443.", 1, 65535, func(j *checkJSON) *int { return &j.Port }),
			expiryWarningDaysField,
			boolField("validate_chain", "Also validate the certificate chain. Defaults to `false`.",
				func(j *checkJSON) *bool { return &j.ValidateChain }),
			timeoutField(),
		},
	},
	{
		block: "domain_expiry", apiType: "domain_expiry",
		desc: "Domain registration expiry check.",
		fields: []checkField{
			strField("domain", "Registered domain name.", func(j *checkJSON) *string { return &j.Domain }).req(),
			expiryWarningDaysField,
			timeoutField(),
		},
	},
	{
		block: "passive", apiType: "passive",
		desc: "Passive (heartbeat) check: fails when no ping arrives within the timeout.",
		fields: []checkField{
			timeoutField(),
		},
	},
	databaseType("pgsql_query", "PostgreSQL", "postgres", "5432", (*checkJSON).pgsql, true),
	databaseType("mysql_query", "MySQL", "mysql", "3306", (*checkJSON).mysql, false),
	{
		block: "redis", apiType: "redis",
		desc: "Redis check: connects, authenticates and sends PING.",
		fields: []checkField{
			hostField("Redis host name or address.").req(),
			portField("6379"),
			intField("db", "Database number to select. Omit for database 0.", 1, 0, func(j *checkJSON) *int { return &j.RedisDB }),
			timeoutField(),
		},
		secrets: []checkSecret{
			stringSecret("password", "Redis password (`AUTH`).", func(j *checkJSON) **string { return &j.RedisPassword }),
		},
	},
	{
		block: "mongodb", apiType: "mongodb", connection: "mongo",
		desc: "MongoDB check: connects and pings the server.",
		fields: []checkField{
			timeoutField(),
		},
		secrets: []checkSecret{
			stringSecret("uri", "MongoDB connection URI, for example `mongodb://user:pass@host:27017/db`. The whole URI is a secret. "+
				"Required unless `connection_id` is set; conflicts with it.",
				func(j *checkJSON) **string { return &j.MongoDBURI }).cred().reqUnlessConnection(),
		},
	},
	{
		block: "ssh", apiType: "ssh",
		desc: "SSH check: connects and reads the server banner. No login is made, so no credentials are needed.",
		fields: []checkField{
			hostField("SSH server host name or address.").req(),
			portField("22"),
			strField("expect_banner", "Text the banner must contain, for example `OpenSSH`.",
				func(j *checkJSON) *string { return &j.ExpectBanner }),
			timeoutField(),
		},
	},
	{
		block: "smtp", apiType: "smtp",
		desc: "SMTP check: connects, optionally upgrades with STARTTLS and authenticates.",
		fields: []checkField{
			hostField("SMTP server host name or address.").req(),
			intField("port", "SMTP port, for example 25 or 587.", 1, 65535, func(j *checkJSON) *int { return &j.Port }).req(),
			boolField("starttls", "Upgrade the connection with STARTTLS. Defaults to `false`.",
				func(j *checkJSON) *bool { return &j.StartTLS }),
			strField("username", "SMTP authentication user name.", func(j *checkJSON) *string { return &j.SMTPUsername }),
			timeoutField(),
		},
		secrets: []checkSecret{
			stringSecret("password", "SMTP authentication password.", func(j *checkJSON) **string { return &j.SMTPPassword }),
		},
	},
	{
		block: "grpc_health", apiType: "grpc_health",
		desc: "gRPC health check: calls the standard `grpc.health.v1` service and expects `SERVING`.",
		fields: []checkField{
			hostField("Target as `host:port`.").req(),
			boolField("use_tls", "Connect with TLS. Defaults to `false`.", func(j *checkJSON) *bool { return &j.UseTLS }),
			timeoutField(),
		},
	},
	{
		block: "websocket", apiType: "websocket",
		desc: "WebSocket check: completes the opening handshake.",
		fields: []checkField{
			strField("url", "`ws://` or `wss://` URL. Must not contain a password: the API masks it on read.",
				func(j *checkJSON) *string { return &j.URL }).req().noURLPassword(),
			timeoutField(),
		},
	},
}

func checkTypeByAPI(apiType string) (checkType, bool) {
	for _, t := range checkTypes {
		if t.apiType == apiType {
			return t, true
		}
	}
	return checkType{}, false
}

// commonCheckFields are the attributes shared by every check. Inheritable
// fields (null = use the Tenant's check defaults) are optional and never
// computed, so a change of the defaults causes no diff (#110).
var commonCheckFields = []checkField{
	strField("name", "Check name.", func(j *checkJSON) *string { return &j.Name }).req(),
	strField("project", "Project the check belongs to.", func(j *checkJSON) *string { return &j.Project }).req(),
	strField("group", "Group within the project.", func(j *checkJSON) *string { return &j.GroupName }),
	strField("description", "Free-text description.", func(j *checkJSON) *string { return &j.Description }),
	strField("interval", "Check interval. Inherited when null."+durationHint,
		func(j *checkJSON) *string { return &j.Duration }).dur(),
	strField("run_mode", "Where the check runs: `saas_only` (platform Probes), `multi_region` (platform and the Tenant's own Probes) or `edge_only` (the Tenant's own Probes; needs `target_regions`). Omit for `saas_only`.",
		func(j *checkJSON) *string { return &j.RunMode }).of("saas_only", "multi_region", "edge_only"),
	{name: "target_regions", desc: "Regions to run in. Omit for all applicable regions selected for the Tenant.", kind: kindStringSet,
		ptr: func(j *checkJSON) any { return &j.TargetRegions }},
	{name: "alert_channels", desc: "Alert channel names. Inherited from the check defaults when null.", kind: kindStringSet,
		ptr: func(j *checkJSON) any { return &j.AlertChannels }},
	strField("severity", "Alert severity. Inherited when null.", func(j *checkJSON) *string { return &j.Severity }).
		of("critical", "warning", "info"),
	strField("re_alert_interval", "Interval between repeated alerts while the check stays unhealthy. Inherited when null."+durationHint,
		func(j *checkJSON) *string { return &j.ReAlertInterval }).dur(),
	intField("retry_count", "Retries before a failure is reported. Inherited when null. Must be at least 1: the API cannot yet distinguish an explicit 0 from unset.",
		1, 0, func(j *checkJSON) *int { return &j.RetryCount }),
	strField("retry_interval", "Wait between retries. Inherited when null."+durationHint,
		func(j *checkJSON) *string { return &j.RetryInterval }).dur(),
	strField("escalation_policy", "Escalation policy name. Inherited when null.",
		func(j *checkJSON) *string { return &j.EscalationPolicyName }),
	intField("edge_min_unhealthy", "Minimum number of unhealthy regions before alerting. Omit to alert directly.",
		1, 0, func(j *checkJSON) *int { return &j.EdgeMinUnhealthy }),
}

// enabledAttr is mapped separately: the API stores a plain boolean, so it
// has a default instead of null.
const enabledAttr = "enabled"

// connectionIDAttr is mapped separately: null must be sent as "" because the
// API keeps a stored reference when the field is omitted.
const connectionIDAttr = "connection_id"

// valueFromAPI converts an API field to its Terraform value. Zero values
// become null, except booleans.
func (f checkField) valueFromAPI(j *checkJSON) attr.Value {
	switch p := f.ptr(j).(type) {
	case *string:
		if *p == "" {
			return types.StringNull()
		}
		return types.StringValue(*p)
	case *int:
		if *p == 0 {
			return types.Int64Null()
		}
		return types.Int64Value(int64(*p))
	case *bool:
		return types.BoolValue(*p)
	case *[]int:
		if len(*p) == 0 {
			return types.SetNull(types.Int64Type)
		}
		elems := make([]attr.Value, len(*p))
		for i, v := range *p {
			elems[i] = types.Int64Value(int64(v))
		}
		return types.SetValueMust(types.Int64Type, elems)
	case *[]string:
		if len(*p) == 0 {
			return types.SetNull(types.StringType)
		}
		elems := make([]attr.Value, len(*p))
		for i, v := range *p {
			elems[i] = types.StringValue(v)
		}
		return types.SetValueMust(types.StringType, elems)
	}
	panic("checkField " + f.name + ": unsupported pointer type")
}

// setAPI stores a Terraform value in the API field. Null and unknown
// values leave the zero value.
func (f checkField) setAPI(j *checkJSON, v attr.Value) {
	if v == nil || v.IsNull() || v.IsUnknown() {
		return
	}
	switch p := f.ptr(j).(type) {
	case *string:
		*p = v.(types.String).ValueString()
	case *int:
		*p = int(v.(types.Int64).ValueInt64())
	case *bool:
		*p = v.(types.Bool).ValueBool()
	case *[]int:
		elems := v.(types.Set).Elements()
		out := make([]int, 0, len(elems))
		for _, e := range elems {
			out = append(out, int(e.(types.Int64).ValueInt64()))
		}
		sort.Ints(out)
		*p = out
	case *[]string:
		elems := v.(types.Set).Elements()
		out := make([]string, 0, len(elems))
		for _, e := range elems {
			out = append(out, e.(types.String).ValueString())
		}
		sort.Strings(out)
		*p = out
	default:
		panic("checkField " + f.name + ": unsupported pointer type")
	}
}

// checkValues is the Terraform side of one check: top-level attributes by
// name and the type block objects by block name. A null object means the
// block is absent.
type checkValues struct {
	attrs  map[string]attr.Value
	blocks map[string]types.Object
}

// usesConnection reports whether connection_id is set (known and not null).
func (v checkValues) usesConnection() bool {
	c, ok := v.attrs[connectionIDAttr].(types.String)
	return ok && !c.IsNull() && !c.IsUnknown()
}

// activeBlock returns the single configured type block.
func (v checkValues) activeBlock() (checkType, types.Object, bool) {
	for _, t := range checkTypes {
		if obj, ok := v.blocks[t.block]; ok && !obj.IsNull() && !obj.IsUnknown() {
			return t, obj, true
		}
	}
	return checkType{}, types.Object{}, false
}

// secretValues holds what to send for each write-only secret of the active
// block: absent keys are omitted (stored value kept), a nil value clears.
type secretValues map[string]attr.Value

// toAPI builds the request body. uuid is set on create only.
func (v checkValues) toAPI(uuid string, secrets secretValues) (checkJSON, diag.Diagnostics) {
	var diags diag.Diagnostics
	j := checkJSON{UUID: uuid}
	for _, f := range commonCheckFields {
		f.setAPI(&j, v.attrs[f.name])
	}
	if enabled, ok := v.attrs[enabledAttr].(types.Bool); ok && !enabled.IsNull() && !enabled.IsUnknown() {
		j.Enabled = enabled.ValueBool()
	} else {
		j.Enabled = true
	}
	connectionID := ""
	if v.usesConnection() {
		connectionID = v.attrs[connectionIDAttr].(types.String).ValueString()
	}
	j.ConnectionID = &connectionID
	t, obj, ok := v.activeBlock()
	if !ok {
		diags.AddError("Missing check type block", "Exactly one check type block ("+checkTypeBlockList()+") is required.")
		return j, diags
	}
	j.Type = t.apiType
	attrs := obj.Attributes()
	for _, f := range t.fields {
		f.setAPI(&j, attrs[f.name])
	}
	for _, s := range t.secrets {
		if value, send := secrets[s.name]; send {
			s.set(&j, value)
		}
	}
	return j, diags
}

// checkValuesFromAPI converts a read. prior supplies the write-only
// versions, which the API does not store. withSecrets selects the resource
// shape (with _wo attributes) or the data source shape.
func checkValuesFromAPI(j *checkJSON, prior checkValues, withSecrets bool) (checkValues, diag.Diagnostics) {
	var diags diag.Diagnostics
	v := checkValues{attrs: map[string]attr.Value{}, blocks: map[string]types.Object{}}
	for _, f := range commonCheckFields {
		v.attrs[f.name] = f.valueFromAPI(j)
	}
	v.attrs[enabledAttr] = types.BoolValue(j.Enabled)
	v.attrs[connectionIDAttr] = types.StringNull()
	if j.ConnectionID != nil && *j.ConnectionID != "" {
		v.attrs[connectionIDAttr] = types.StringValue(*j.ConnectionID)
	}
	active, known := checkTypeByAPI(j.Type)
	if !known {
		diags.AddError("Unsupported check type",
			"Check "+j.UUID+" has type \""+j.Type+"\", which this provider version does not manage. Supported types: "+checkTypeBlockList()+".")
	}
	for _, t := range checkTypes {
		attrTypes := t.attrTypes(withSecrets)
		if !known || t.apiType != active.apiType {
			v.blocks[t.block] = types.ObjectNull(attrTypes)
			continue
		}
		attrs := make(map[string]attr.Value, len(attrTypes))
		for _, f := range t.fields {
			attrs[f.name] = f.valueFromAPI(j)
		}
		if withSecrets {
			var priorAttrs map[string]attr.Value
			if obj, ok := prior.blocks[t.block]; ok && !obj.IsNull() && !obj.IsUnknown() {
				priorAttrs = obj.Attributes()
			}
			for _, s := range t.secrets {
				// Write-only values are never stored in state.
				attrs[s.name+"_wo"] = types.StringNull()
				if s.isMap {
					attrs[s.name+"_wo"] = types.MapNull(types.StringType)
				}
				version := types.Int64Null()
				if pv, ok := priorAttrs[s.name+"_wo_version"].(types.Int64); ok && !pv.IsUnknown() {
					version = pv
				}
				attrs[s.name+"_wo_version"] = version
			}
		}
		obj, d := types.ObjectValue(attrTypes, attrs)
		diags.Append(d...)
		v.blocks[t.block] = obj
	}
	return v, diags
}

func checkTypeBlockList() string {
	s := ""
	for i, t := range checkTypes {
		if i > 0 {
			s += ", "
		}
		s += t.block
	}
	return s
}

// connectionUse tells secretsToSend whether the planned and the prior state
// use connection_id.
type connectionUse struct{ plan, state bool }

// secretsToSend decides which write-only secrets of the active block go into
// the request (#110): on create every configured secret; on update only
// secrets whose _wo_version changed, sending a clear when the new
// configuration has no value.
//
// With connection_id the Connection provides the credentials (#115), so
// credential secrets are always cleared. When a check stops using a
// Connection, its credential secrets are sent even with an unchanged
// version, because the server no longer holds them.
func secretsToSend(t checkType, config, state map[string]attr.Value, create bool, conn connectionUse) secretValues {
	out := secretValues{}
	for _, s := range t.secrets {
		if s.credential && conn.plan {
			out[s.name] = nil
			continue
		}
		value := config[s.name+"_wo"]
		hasValue := value != nil && !value.IsNull() && !value.IsUnknown()
		if create {
			if hasValue {
				out[s.name] = value
			}
			continue
		}
		planVersion, stateVersion := config[s.name+"_wo_version"], state[s.name+"_wo_version"]
		if attrEqual(planVersion, stateVersion) && !(s.credential && conn.state) {
			continue
		}
		if hasValue {
			out[s.name] = value
		} else {
			out[s.name] = nil
		}
	}
	return out
}

func attrEqual(a, b attr.Value) bool {
	aNull := a == nil || a.IsNull()
	bNull := b == nil || b.IsNull()
	if aNull || bNull {
		return aNull == bNull
	}
	return a.Equal(b)
}
