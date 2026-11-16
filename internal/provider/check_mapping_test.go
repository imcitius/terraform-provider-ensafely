package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCheckSchemasAreValid(t *testing.T) {
	ctx := context.Background()
	var rs resource.SchemaResponse
	newCheckResource().Schema(ctx, resource.SchemaRequest{}, &rs)
	if diags := rs.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("resource schema: %v", diags)
	}
	var ds datasource.SchemaResponse
	newCheckDataSource().Schema(ctx, datasource.SchemaRequest{}, &ds)
	if diags := ds.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatalf("data source schema: %v", diags)
	}
	// Inheritable fields must be optional and not computed (#110).
	for _, name := range []string{"interval", "alert_channels", "severity", "re_alert_interval", "retry_count", "retry_interval", "escalation_policy"} {
		a := rs.Schema.Attributes[name]
		if a == nil || !a.IsOptional() || a.IsComputed() {
			t.Errorf("%s must be optional and not computed", name)
		}
	}
	http := rs.Schema.Blocks["http"].GetNestedObject().GetAttributes()
	for _, name := range []string{"basic_auth_password_wo", "headers_wo"} {
		if !http[name].IsWriteOnly() || !http[name].IsSensitive() {
			t.Errorf("http.%s must be write-only and sensitive", name)
		}
	}
	// Every secret of every type is write-only (#115): no _wo value can
	// reach plan or state.
	secrets := 0
	for _, ct := range checkTypes {
		nested := rs.Schema.Blocks[ct.block].GetNestedObject().GetAttributes()
		for name, a := range nested {
			if strings.HasSuffix(name, "_wo") {
				secrets++
				if !a.IsWriteOnly() || !a.IsSensitive() {
					t.Errorf("%s.%s must be write-only and sensitive", ct.block, name)
				}
				if _, ok := nested[name+"_version"]; !ok {
					t.Errorf("%s.%s has no _wo_version", ct.block, name)
				}
			}
		}
	}
	if secrets != 7 { // http (2), pgsql_query, mysql_query, redis, mongodb, smtp
		t.Errorf("found %d write-only secrets, want 7", secrets)
	}
	if c := rs.Schema.Attributes[connectionIDAttr]; c == nil || !c.IsOptional() || c.IsComputed() {
		t.Error("connection_id must be optional and not computed")
	}
	if _, ok := ds.Schema.Attributes["http"].(interface{ IsWriteOnly() bool }); !ok {
		t.Fatal("data source http must be an attribute")
	}
}

// mappingCase is one check type: the API read (a CheckRead the server
// returns, secrets masked) and the request the provider sends back for the
// resulting Terraform values. Every type also runs with a minimal read, in
// which all optional fields must map to null.
type mappingCase struct {
	name     string
	read     string
	attrs    map[string]attr.Value
	request  string
	minimal  string
	minBlock map[string]attr.Value
}

const commonRead = `"uuid":"3f1c9a52-6b5e-4f4e-9d0e-0a7b2c3d4e5f","name":"api","project":"shop","group_name":"edge",
"description":"Public API","enabled":false,"duration":"1m","severity":"warning","alert_channels":["slack","ops"],
"re_alert_interval":"2h","retry_count":2,"retry_interval":"10s","escalation_policy_name":"on-call","run_mode":"multi_region",
"target_regions":["eu","us"],"edge_min_unhealthy":2,"health_state":"healthy","is_healthy":true,"last_run":"Never","last_message":"",
"auth":{},"mysql":{},"pgsql":{}`

const commonRequest = `"name":"api","project":"shop","group_name":"edge","description":"Public API","enabled":false,"duration":"1m",
"severity":"warning","alert_channels":["ops","slack"],"re_alert_interval":"2h","retry_count":2,"retry_interval":"10s",
"escalation_policy_name":"on-call","run_mode":"multi_region","target_regions":["eu","us"],"edge_min_unhealthy":2,"connection_id":""`

func str(s string) attr.Value { return types.StringValue(s) }
func num(n int64) attr.Value  { return types.Int64Value(n) }
func boolean(b bool) attr.Value {
	return types.BoolValue(b)
}

var mappingCases = []mappingCase{
	{
		name: "http",
		read: `"type":"http","url":"https://api.example.com/health","timeout":"5s","answer":"ok","answer_present":true,"code":[200,204],
"headers":[{"Authorization":"****"}],"skip_check_ssl":true,"ssl_expiration_period":"720h","stop_follow_redirects":true,
"auth":{"user":"monitor","password":"****"}`,
		attrs: map[string]attr.Value{
			"url": str("https://api.example.com/health"), "timeout": str("5s"), "answer": str("ok"), "answer_present": boolean(true),
			"status_codes": types.SetValueMust(types.Int64Type, []attr.Value{num(204), num(200)}), "skip_check_ssl": boolean(true),
			"ssl_expiration_period": str("720h"), "stop_follow_redirects": boolean(true), "basic_auth_user": str("monitor"),
			"basic_auth_password_wo": types.StringNull(), "basic_auth_password_wo_version": types.Int64Null(),
			"headers_wo": types.MapNull(types.StringType), "headers_wo_version": types.Int64Null(),
		},
		request: `"type":"http","url":"https://api.example.com/health","timeout":"5s","answer":"ok","answer_present":true,"code":[200,204],
"skip_check_ssl":true,"ssl_expiration_period":"720h","stop_follow_redirects":true,"auth":{"user":"monitor"}`,
		minimal: `"type":"http","url":"https://example.com"`,
		minBlock: map[string]attr.Value{
			"url": str("https://example.com"), "timeout": types.StringNull(), "answer": types.StringNull(), "answer_present": boolean(false),
			"status_codes": types.SetNull(types.Int64Type), "skip_check_ssl": boolean(false), "ssl_expiration_period": types.StringNull(),
			"stop_follow_redirects": boolean(false), "basic_auth_user": types.StringNull(),
		},
	},
	{
		name:     "tcp",
		read:     `"type":"tcp","host":"db.example.com","port":5432,"timeout":"3s"`,
		attrs:    map[string]attr.Value{"host": str("db.example.com"), "port": num(5432), "timeout": str("3s")},
		request:  `"type":"tcp","host":"db.example.com","port":5432,"timeout":"3s"`,
		minimal:  `"type":"tcp","host":"h","port":1`,
		minBlock: map[string]attr.Value{"host": str("h"), "port": num(1), "timeout": types.StringNull()},
	},
	{
		name:     "icmp",
		read:     `"type":"icmp","host":"10.0.0.1","count":3,"timeout":"2s"`,
		attrs:    map[string]attr.Value{"host": str("10.0.0.1"), "count": num(3), "timeout": str("2s")},
		request:  `"type":"icmp","host":"10.0.0.1","count":3,"timeout":"2s"`,
		minimal:  `"type":"icmp","host":"h"`,
		minBlock: map[string]attr.Value{"host": str("h"), "count": types.Int64Null(), "timeout": types.StringNull()},
	},
	{
		name: "dns",
		read: `"type":"dns","host":"1.1.1.1:53","domain":"example.com","record_type":"MX","expected":"mail","timeout":"2s"`,
		attrs: map[string]attr.Value{"host": str("1.1.1.1:53"), "domain": str("example.com"), "record_type": str("MX"),
			"expected": str("mail"), "timeout": str("2s")},
		request: `"type":"dns","host":"1.1.1.1:53","domain":"example.com","record_type":"MX","expected":"mail","timeout":"2s"`,
		minimal: `"type":"dns","domain":"example.com"`,
		minBlock: map[string]attr.Value{"host": types.StringNull(), "domain": str("example.com"), "record_type": types.StringNull(),
			"expected": types.StringNull(), "timeout": types.StringNull()},
	},
	{
		name: "ssl_cert",
		read: `"type":"ssl_cert","host":"example.com","port":8443,"expiry_warning_days":14,"validate_chain":true,"timeout":"4s"`,
		attrs: map[string]attr.Value{"host": str("example.com"), "port": num(8443), "expiry_warning_days": num(14),
			"validate_chain": boolean(true), "timeout": str("4s")},
		request: `"type":"ssl_cert","host":"example.com","port":8443,"expiry_warning_days":14,"validate_chain":true,"timeout":"4s"`,
		minimal: `"type":"ssl_cert","host":"example.com"`,
		minBlock: map[string]attr.Value{"host": str("example.com"), "port": types.Int64Null(), "expiry_warning_days": types.Int64Null(),
			"validate_chain": boolean(false), "timeout": types.StringNull()},
	},
	{
		name:    "domain_expiry",
		read:    `"type":"domain_expiry","domain":"example.com","expiry_warning_days":30,"timeout":"10s"`,
		attrs:   map[string]attr.Value{"domain": str("example.com"), "expiry_warning_days": num(30), "timeout": str("10s")},
		request: `"type":"domain_expiry","domain":"example.com","expiry_warning_days":30,"timeout":"10s"`,
		minimal: `"type":"domain_expiry","domain":"example.com"`,
		minBlock: map[string]attr.Value{"domain": str("example.com"), "expiry_warning_days": types.Int64Null(),
			"timeout": types.StringNull()},
	},
	{
		name:     "passive",
		read:     `"type":"passive","timeout":"15m"`,
		attrs:    map[string]attr.Value{"timeout": str("15m")},
		request:  `"type":"passive","timeout":"15m"`,
		minimal:  `"type":"passive"`,
		minBlock: map[string]attr.Value{"timeout": types.StringNull()},
	},
	{
		name: "pgsql_query",
		read: `"type":"pgsql_query","host":"db.example.com","port":6432,"timeout":"5s",
"pgsql":{"username":"monitor","password":"****","dbname":"shop","sslmode":"require","query":"SELECT count(*) FROM orders","response":"42"}`,
		attrs: map[string]attr.Value{"host": str("db.example.com"), "port": num(6432), "timeout": str("5s"), "username": str("monitor"),
			"db_name": str("shop"), "ssl_mode": str("require"), "query": str("SELECT count(*) FROM orders"), "response": str("42"),
			"password_wo": types.StringNull(), "password_wo_version": types.Int64Null()},
		request: `"type":"pgsql_query","host":"db.example.com","port":6432,"timeout":"5s",
"pgsql":{"username":"monitor","dbname":"shop","sslmode":"require","query":"SELECT count(*) FROM orders","response":"42"}`,
		minimal: `"type":"pgsql_query","host":"db"`,
		minBlock: map[string]attr.Value{"host": str("db"), "port": types.Int64Null(), "timeout": types.StringNull(), "username": types.StringNull(),
			"db_name": types.StringNull(), "ssl_mode": types.StringNull(), "query": types.StringNull(), "response": types.StringNull()},
	},
	{
		name: "mysql_query",
		read: `"type":"mysql_query","host":"db.example.com","port":3307,"timeout":"5s",
"mysql":{"username":"monitor","password":"****","dbname":"shop","query":"SELECT 2","response":"2"}`,
		attrs: map[string]attr.Value{"host": str("db.example.com"), "port": num(3307), "timeout": str("5s"), "username": str("monitor"),
			"db_name": str("shop"), "query": str("SELECT 2"), "response": str("2"),
			"password_wo": types.StringNull(), "password_wo_version": types.Int64Null()},
		request: `"type":"mysql_query","host":"db.example.com","port":3307,"timeout":"5s",
"mysql":{"username":"monitor","dbname":"shop","query":"SELECT 2","response":"2"}`,
		minimal: `"type":"mysql_query","host":"db"`,
		minBlock: map[string]attr.Value{"host": str("db"), "port": types.Int64Null(), "timeout": types.StringNull(), "username": types.StringNull(),
			"db_name": types.StringNull(), "query": types.StringNull(), "response": types.StringNull()},
	},
	{
		name: "redis",
		read: `"type":"redis","host":"cache.example.com","port":6380,"redis_db":3,"redis_password":"****","timeout":"2s"`,
		attrs: map[string]attr.Value{"host": str("cache.example.com"), "port": num(6380), "db": num(3), "timeout": str("2s"),
			"password_wo": types.StringNull(), "password_wo_version": types.Int64Null()},
		request:  `"type":"redis","host":"cache.example.com","port":6380,"redis_db":3,"timeout":"2s"`,
		minimal:  `"type":"redis","host":"cache"`,
		minBlock: map[string]attr.Value{"host": str("cache"), "port": types.Int64Null(), "db": types.Int64Null(), "timeout": types.StringNull()},
	},
	{
		name:     "mongodb",
		read:     `"type":"mongodb","mongodb_uri":"****","timeout":"5s"`,
		attrs:    map[string]attr.Value{"timeout": str("5s"), "uri_wo": types.StringNull(), "uri_wo_version": types.Int64Null()},
		request:  `"type":"mongodb","timeout":"5s"`,
		minimal:  `"type":"mongodb"`,
		minBlock: map[string]attr.Value{"timeout": types.StringNull()},
	},
	{
		name:     "ssh",
		read:     `"type":"ssh","host":"bastion.example.com","port":2222,"expect_banner":"OpenSSH","timeout":"3s"`,
		attrs:    map[string]attr.Value{"host": str("bastion.example.com"), "port": num(2222), "expect_banner": str("OpenSSH"), "timeout": str("3s")},
		request:  `"type":"ssh","host":"bastion.example.com","port":2222,"expect_banner":"OpenSSH","timeout":"3s"`,
		minimal:  `"type":"ssh","host":"bastion"`,
		minBlock: map[string]attr.Value{"host": str("bastion"), "port": types.Int64Null(), "expect_banner": types.StringNull(), "timeout": types.StringNull()},
	},
	{
		name: "smtp",
		read: `"type":"smtp","host":"mail.example.com","port":587,"starttls":true,"smtp_username":"monitor","smtp_password":"****","timeout":"5s"`,
		attrs: map[string]attr.Value{"host": str("mail.example.com"), "port": num(587), "starttls": boolean(true), "username": str("monitor"),
			"timeout": str("5s"), "password_wo": types.StringNull(), "password_wo_version": types.Int64Null()},
		request: `"type":"smtp","host":"mail.example.com","port":587,"starttls":true,"smtp_username":"monitor","timeout":"5s"`,
		minimal: `"type":"smtp","host":"mail","port":25`,
		minBlock: map[string]attr.Value{"host": str("mail"), "port": num(25), "starttls": boolean(false), "username": types.StringNull(),
			"timeout": types.StringNull()},
	},
	{
		name:     "grpc_health",
		read:     `"type":"grpc_health","host":"api.example.com:443","use_tls":true,"timeout":"2s"`,
		attrs:    map[string]attr.Value{"host": str("api.example.com:443"), "use_tls": boolean(true), "timeout": str("2s")},
		request:  `"type":"grpc_health","host":"api.example.com:443","use_tls":true,"timeout":"2s"`,
		minimal:  `"type":"grpc_health","host":"api:50051"`,
		minBlock: map[string]attr.Value{"host": str("api:50051"), "use_tls": boolean(false), "timeout": types.StringNull()},
	},
	{
		name:     "websocket",
		read:     `"type":"websocket","url":"wss://ws.example.com/socket","timeout":"4s"`,
		attrs:    map[string]attr.Value{"url": str("wss://ws.example.com/socket"), "timeout": str("4s")},
		request:  `"type":"websocket","url":"wss://ws.example.com/socket","timeout":"4s"`,
		minimal:  `"type":"websocket","url":"ws://ws"`,
		minBlock: map[string]attr.Value{"url": str("ws://ws"), "timeout": types.StringNull()},
	},
}

// TestCheckSecretsPerType covers the write-only secret of every new type
// (#115): create sends it in the API field, an update with an unchanged
// version omits it (the server keeps it), a bump without a value clears it,
// and a read never stores it.
func TestCheckSecretsPerType(t *testing.T) {
	tests := []struct {
		block, read, secret, sent, cleared string
	}{
		{"pgsql_query", `"host":"db"`, "password", `"pgsql":{"password":"s3cret"}`, `"pgsql":{"password":""}`},
		{"mysql_query", `"host":"db"`, "password", `"mysql":{"password":"s3cret"}`, `"mysql":{"password":""}`},
		{"redis", `"host":"cache"`, "password", `"redis_password":"s3cret"`, `"redis_password":""`},
		{"smtp", `"host":"mail","port":25`, "password", `"smtp_password":"s3cret"`, `"smtp_password":""`},
		{"mongodb", ``, "uri", `"mongodb_uri":"s3cret"`, `"mongodb_uri":""`},
	}
	for _, tc := range tests {
		t.Run(tc.block, func(t *testing.T) {
			ct, ok := checkTypeByAPI(tc.block)
			if !ok {
				t.Fatalf("no type %s", tc.block)
			}
			base := `"type":"` + tc.block + `","name":"n","project":"p","enabled":true,"connection_id":""`
			if tc.read != "" {
				base += "," + tc.read
			}
			v := fromAPI(t, `"uuid":"u",`+base, checkValues{}, true)
			request := func(secrets secretValues) checkJSON {
				body, diags := v.toAPI("", secrets)
				if diags.HasError() {
					t.Fatal(diags)
				}
				return body
			}
			wo, version := tc.secret+"_wo", tc.secret+"_wo_version"
			config := func(value attr.Value, ver attr.Value) map[string]attr.Value {
				return map[string]attr.Value{wo: value, version: ver}
			}
			state := config(types.StringNull(), num(1))

			assertJSON(t, request(secretsToSend(ct, config(str("s3cret"), num(1)), nil, true, connectionUse{})), base+","+tc.sent)
			assertJSON(t, request(secretsToSend(ct, config(str("other"), num(1)), state, false, connectionUse{})), base)
			assertJSON(t, request(secretsToSend(ct, config(types.StringNull(), num(2)), state, false, connectionUse{})), base+","+tc.cleared)

			read := fromAPI(t, `"uuid":"u",`+base+`,"pgsql":{"password":"****"},"mysql":{"password":"****"},`+
				`"redis_password":"****","smtp_password":"****","mongodb_uri":"****"`,
				checkValues{blocks: map[string]types.Object{tc.block: types.ObjectValueMust(ct.attrTypes(true), withVersion(t, ct, version, num(7)))}}, true)
			attrs := read.blocks[tc.block].Attributes()
			if !attrs[wo].IsNull() || !attrs[version].Equal(num(7)) {
				t.Errorf("read stored %s = %v, %s = %v", wo, attrs[wo], version, attrs[version])
			}
		})
	}
}

// withVersion returns a null block object of ct with one _wo_version set.
func withVersion(t *testing.T, ct checkType, name string, version attr.Value) map[string]attr.Value {
	t.Helper()
	attrs := map[string]attr.Value{}
	for n, typ := range ct.attrTypes(true) {
		attrs[n] = nullOf(typ)
	}
	attrs[name] = version
	return attrs
}

// TestCheckConnectionMapping covers connection_id (#115): a read maps it to
// state, it is sent as given, and null is sent as "" so an update removes a
// stored reference (the API keeps it when the field is omitted). With a
// Connection, credential secrets are always cleared; when a check stops
// using one, they are sent again although their version did not change.
func TestCheckConnectionMapping(t *testing.T) {
	const connID = "6c1f0e8a-2b7d-4c3e-9f10-8a2b3c4d5e6f"
	ct, _ := checkTypeByAPI("pgsql_query")
	read := `"uuid":"u","type":"pgsql_query","name":"n","project":"p","enabled":true,"connection_id":"` + connID +
		`","pgsql":{"query":"SELECT 1"},"mysql":{},"auth":{}`
	v := fromAPI(t, read, checkValues{}, true)
	if !v.attrs[connectionIDAttr].Equal(str(connID)) {
		t.Fatalf("connection_id = %v", v.attrs[connectionIDAttr])
	}
	if !v.usesConnection() {
		t.Fatal("usesConnection = false")
	}
	if attrs := v.blocks["pgsql_query"].Attributes(); !attrs["host"].IsNull() || !attrs["username"].IsNull() {
		t.Errorf("a Connection check must not report inline host or user: %v", attrs)
	}
	ds := checkDataSourceValues(decodeCheck(t, read))
	if !ds.attrs[connectionIDAttr].Equal(str(connID)) {
		t.Errorf("data source connection_id = %v", ds.attrs[connectionIDAttr])
	}

	base := `"type":"pgsql_query","name":"n","project":"p","enabled":true,"pgsql":{"query":"SELECT 1"`
	config := map[string]attr.Value{"password_wo": str("inline"), "password_wo_version": num(1)}
	state := map[string]attr.Value{"password_wo": types.StringNull(), "password_wo_version": num(1)}

	body, _ := v.toAPI("", secretsToSend(ct, config, state, false, connectionUse{plan: true, state: true}))
	assertJSON(t, body, base+`,"password":""},"connection_id":"`+connID+`"`)
	body, _ = v.toAPI("new", secretsToSend(ct, config, nil, true, connectionUse{plan: true}))
	assertJSON(t, body, `"uuid":"new",`+base+`,"password":""},"connection_id":"`+connID+`"`)

	// Switching back to inline credentials: connection_id "" and the
	// password is sent with an unchanged version.
	v.attrs[connectionIDAttr] = types.StringNull()
	body, _ = v.toAPI("", secretsToSend(ct, config, state, false, connectionUse{state: true}))
	assertJSON(t, body, base+`,"password":"inline"},"connection_id":""`)
	// Without a Connection on either side an unchanged version sends nothing.
	body, _ = v.toAPI("", secretsToSend(ct, config, state, false, connectionUse{}))
	assertJSON(t, body, base+`},"connection_id":""`)

	// Non-credential secrets follow the version rule even with a Connection.
	httpType, _ := checkTypeByAPI("http")
	headers := types.MapValueMust(types.StringType, map[string]attr.Value{"X-Key": str("k")})
	got := secretsToSend(httpType, httpSecrets(types.StringNull(), types.Int64Null(), headers, num(1)), nil, true, connectionUse{plan: true})
	if _, ok := got["headers"]; !ok || got["basic_auth_password"] != nil {
		t.Errorf("http with a Connection: got %v, want headers sent and basic_auth_password cleared", got)
	}
	if _, ok := got["basic_auth_password"]; !ok {
		t.Error("basic_auth_password must be cleared with a Connection")
	}
}

func decodeCheck(t *testing.T, body string) *checkJSON {
	t.Helper()
	var j checkJSON
	if err := json.Unmarshal([]byte("{"+body+"}"), &j); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return &j
}

func assertJSON(t *testing.T, got any, want string) {
	t.Helper()
	gotRaw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w map[string]any
	if err := json.Unmarshal(gotRaw, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte("{"+want+"}"), &w); err != nil {
		t.Fatalf("bad expectation %s: %v", want, err)
	}
	gs, _ := json.Marshal(g)
	ws, _ := json.Marshal(w)
	if string(gs) != string(ws) {
		t.Errorf("request mismatch\n got: %s\nwant: %s", gs, ws)
	}
}

func assertValues(t *testing.T, where string, got, want map[string]attr.Value) {
	t.Helper()
	for name, w := range want {
		if g := got[name]; g == nil || !g.Equal(w) {
			t.Errorf("%s.%s = %v, want %v", where, name, g, w)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s.%s is not covered by the test", where, name)
		}
	}
}

func fromAPI(t *testing.T, body string, prior checkValues, withSecrets bool) checkValues {
	t.Helper()
	v, diags := checkValuesFromAPI(decodeCheck(t, body), prior, withSecrets)
	if diags.HasError() {
		t.Fatalf("checkValuesFromAPI: %v", diags)
	}
	return v
}

// TestCheckMappingPerType covers HCL values ↔ API JSON for every type: a
// read maps to the expected Terraform values, other type blocks are null,
// and the values map back to the expected request. Secrets in a read are
// masked and never reach the values; with no secret to send the request
// omits them, so the server keeps the stored ones.
func TestCheckMappingPerType(t *testing.T) {
	commonValues := map[string]attr.Value{
		"name": str("api"), "project": str("shop"), "group": str("edge"), "description": str("Public API"), "enabled": boolean(false),
		"interval": str("1m"), "severity": str("warning"), "re_alert_interval": str("2h"), "retry_count": num(2), "retry_interval": str("10s"),
		"escalation_policy": str("on-call"), "run_mode": str("multi_region"), "edge_min_unhealthy": num(2),
		"alert_channels": types.SetValueMust(types.StringType, []attr.Value{str("slack"), str("ops")}),
		"target_regions": types.SetValueMust(types.StringType, []attr.Value{str("eu"), str("us")}),
		"connection_id":  types.StringNull(),
	}
	for _, tc := range mappingCases {
		t.Run(tc.name, func(t *testing.T) {
			v := fromAPI(t, commonRead+","+tc.read, checkValues{}, true)
			assertValues(t, "check", v.attrs, commonValues)
			for _, ct := range checkTypes {
				if ct.block != tc.name && !v.blocks[ct.block].IsNull() {
					t.Errorf("block %s should be null", ct.block)
				}
			}
			assertValues(t, tc.name, v.blocks[tc.name].Attributes(), tc.attrs)
			body, diags := v.toAPI("", nil)
			if diags.HasError() {
				t.Fatal(diags)
			}
			assertJSON(t, body, commonRequest+","+tc.request)

			// Data source shape: same values, without write-only attributes.
			ds := fromAPI(t, commonRead+","+tc.read, checkValues{}, false)
			for name := range ds.blocks[tc.name].Attributes() {
				if strings.HasSuffix(name, "_wo") || strings.HasSuffix(name, "_wo_version") {
					t.Errorf("data source exposes %s", name)
				}
			}
		})
		t.Run(tc.name+"/minimal", func(t *testing.T) {
			v := fromAPI(t, `"uuid":"u","name":"n","project":"p","enabled":true,"duration":"","auth":{},"mysql":{},"pgsql":{},`+tc.minimal, checkValues{}, false)
			want := map[string]attr.Value{"name": str("n"), "project": str("p"), "enabled": boolean(true), "connection_id": types.StringNull()}
			for _, f := range commonCheckFields {
				if _, ok := want[f.name]; !ok {
					want[f.name] = f.valueFromAPI(&checkJSON{})
				}
			}
			assertValues(t, "check", v.attrs, want)
			assertValues(t, tc.name, v.blocks[tc.name].Attributes(), tc.minBlock)
			body, diags := v.toAPI("new-uuid", nil)
			if diags.HasError() {
				t.Fatal(diags)
			}
			assertJSON(t, body, `"uuid":"new-uuid","name":"n","project":"p","enabled":true,"connection_id":"",`+tc.minimal)
		})
	}
}

func TestCheckUnsupportedType(t *testing.T) {
	_, diags := checkValuesFromAPI(decodeCheck(t, `"uuid":"u","type":"pgsql_replication","name":"n","project":"p","host":"h"`), checkValues{}, true)
	if !diags.HasError() || !strings.Contains(diags[0].Detail(), `"pgsql_replication"`) {
		t.Fatalf("expected an unsupported type error, got %v", diags)
	}
	ds := checkDataSourceValues(decodeCheck(t, `"uuid":"u","type":"pgsql_replication","name":"n","project":"p","host":"h"`))
	if !ds.attrs["name"].Equal(str("n")) {
		t.Fatalf("data source lost common fields: %v", ds.attrs)
	}
	for name, obj := range ds.blocks {
		if !obj.IsNull() {
			t.Errorf("block %s should be null for an unmanaged type", name)
		}
	}
}

func httpType(t *testing.T) checkType {
	t.Helper()
	ct, ok := checkTypeByAPI("http")
	if !ok {
		t.Fatal("no http type")
	}
	return ct
}

func httpSecrets(password attr.Value, passwordVersion attr.Value, headers attr.Value, headersVersion attr.Value) map[string]attr.Value {
	return map[string]attr.Value{
		"basic_auth_password_wo": password, "basic_auth_password_wo_version": passwordVersion,
		"headers_wo": headers, "headers_wo_version": headersVersion,
	}
}

// TestCheckWriteOnlySecrets covers the _wo/_wo_version rule (#110): create
// sends configured secrets; update sends a secret only when its version
// changed, and clears it when the version changed and the value was
// removed. Read never puts a secret into state and keeps the version.
func TestCheckWriteOnlySecrets(t *testing.T) {
	ct := httpType(t)
	headers := types.MapValueMust(types.StringType, map[string]attr.Value{"X-Token": str("t0k"), "Authorization": str("Bearer abc")})
	v := fromAPI(t, `"uuid":"u","type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x"`, checkValues{}, true)

	request := func(secrets secretValues) checkJSON {
		body, diags := v.toAPI("", secrets)
		if diags.HasError() {
			t.Fatal(diags)
		}
		return body
	}

	created := request(secretsToSend(ct, httpSecrets(str("pw1"), num(1), headers, num(1)), nil, true, connectionUse{}))
	assertJSON(t, created, `"type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x",
"auth":{"password":"pw1"},"headers":[{"Authorization":"Bearer abc"},{"X-Token":"t0k"}]`)

	createdWithout := request(secretsToSend(ct, httpSecrets(types.StringNull(), types.Int64Null(), types.MapNull(types.StringType), types.Int64Null()), nil, true, connectionUse{}))
	assertJSON(t, createdWithout, `"type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x"`)

	state := httpSecrets(types.StringNull(), num(1), types.MapNull(types.StringType), num(1))
	unchanged := request(secretsToSend(ct, httpSecrets(str("pw2"), num(1), headers, num(1)), state, false, connectionUse{}))
	assertJSON(t, unchanged, `"type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x"`)

	bumped := request(secretsToSend(ct, httpSecrets(str("pw2"), num(2), headers, num(1)), state, false, connectionUse{}))
	assertJSON(t, bumped, `"type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x","auth":{"password":"pw2"}`)

	cleared := request(secretsToSend(ct, httpSecrets(types.StringNull(), num(2), types.MapNull(types.StringType), types.Int64Null()), state, false, connectionUse{}))
	assertJSON(t, cleared, `"type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x","auth":{"password":""},"headers":[]`)

	// A read keeps the prior versions and never stores a secret, even
	// though the API reports that secrets are set.
	prior := checkValues{blocks: map[string]types.Object{"http": types.ObjectValueMust(ct.attrTypes(true), map[string]attr.Value{
		"url": str("https://e.x"), "timeout": types.StringNull(), "answer": types.StringNull(), "answer_present": boolean(false),
		"status_codes": types.SetNull(types.Int64Type), "skip_check_ssl": boolean(false), "ssl_expiration_period": types.StringNull(),
		"stop_follow_redirects": boolean(false), "basic_auth_user": types.StringNull(),
		"basic_auth_password_wo": types.StringNull(), "basic_auth_password_wo_version": num(3),
		"headers_wo": types.MapNull(types.StringType), "headers_wo_version": num(4),
	})}}
	read := fromAPI(t, `"uuid":"u","type":"http","name":"n","project":"p","enabled":true,"connection_id":"","url":"https://e.x",
"auth":{"password":"****"},"headers":[{"X-Token":"****"}]`, prior, true)
	attrs := read.blocks["http"].Attributes()
	if !attrs["basic_auth_password_wo"].IsNull() || !attrs["headers_wo"].IsNull() {
		t.Errorf("secrets reached state: %v", attrs)
	}
	if !attrs["basic_auth_password_wo_version"].Equal(num(3)) || !attrs["headers_wo_version"].Equal(num(4)) {
		t.Errorf("versions not kept: %v", attrs)
	}
}

func TestValidateCheckBlocks(t *testing.T) {
	null := func() map[string]types.Object {
		m := map[string]types.Object{}
		for _, ct := range checkTypes {
			m[ct.block] = types.ObjectNull(ct.attrTypes(true))
		}
		return m
	}
	tests := []struct {
		name   string
		blocks func() map[string]types.Object
		want   string
	}{
		{"none", null, "Missing check type block"},
		{"two", func() map[string]types.Object {
			m := null()
			m["tcp"] = objectOf(t, "tcp")
			m["icmp"] = objectOf(t, "icmp")
			return m
		}, "Conflicting check type blocks"},
		{"one", func() map[string]types.Object { m := null(); m["passive"] = objectOf(t, "passive"); return m }, ""},
		{"unknown", func() map[string]types.Object {
			m := null()
			m["tcp"] = types.ObjectUnknown(checkTypes[1].attrTypes(true))
			return m
		}, ""},
		{"url password", func() map[string]types.Object {
			m := null()
			o := objectOf(t, "http")
			attrs := o.Attributes()
			attrs["url"] = str("https://u:secret@example.com")
			m["http"] = types.ObjectValueMust(httpType(t).attrTypes(true), attrs)
			return m
		}, "Password in URL"},
		{"missing required", func() map[string]types.Object {
			m := null()
			attrs := objectOf(t, "tcp").Attributes()
			attrs["port"] = types.Int64Null()
			m["tcp"] = types.ObjectValueMust(checkTypes[1].attrTypes(true), attrs)
			return m
		}, "Missing required argument"},
		{"url user only", func() map[string]types.Object {
			m := null()
			o := objectOf(t, "http")
			attrs := o.Attributes()
			attrs["url"] = str("https://u@example.com")
			m["http"] = types.ObjectValueMust(httpType(t).attrTypes(true), attrs)
			return m
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			validateCheckConfig(types.StringNull(), tc.blocks(), &diags)
			if tc.want == "" {
				if diags.HasError() {
					t.Fatalf("unexpected error: %v", diags)
				}
				return
			}
			if !diags.HasError() || diags[0].Summary() != tc.want {
				t.Fatalf("want %q, got %v", tc.want, diags)
			}
		})
	}
}

// objectOf returns a block object with every attribute null and the
// required ones set.
func objectOf(t *testing.T, block string) types.Object {
	t.Helper()
	for _, ct := range checkTypes {
		if ct.block != block {
			continue
		}
		attrs := map[string]attr.Value{}
		for name, typ := range ct.attrTypes(true) {
			attrs[name] = nullOf(typ)
		}
		for _, f := range ct.fields {
			if f.required && f.kind == kindString {
				attrs[f.name] = str("example.com")
			} else if f.required && f.kind == kindInt {
				attrs[f.name] = num(1)
			}
		}
		return types.ObjectValueMust(ct.attrTypes(true), attrs)
	}
	t.Fatalf("no block %s", block)
	return types.Object{}
}

func nullOf(typ attr.Type) attr.Value {
	switch typ := typ.(type) {
	case types.SetType:
		return types.SetNull(typ.ElemType)
	case types.MapType:
		return types.MapNull(typ.ElemType)
	}
	switch typ {
	case types.Int64Type:
		return types.Int64Null()
	case types.BoolType:
		return types.BoolNull()
	}
	return types.StringNull()
}

// TestValidateCheckConnection covers the connection_id rules (#115): it
// replaces the fields a Connection supplies, conflicts with inline
// credentials, and is rejected for types the server cannot hydrate.
func TestValidateCheckConnection(t *testing.T) {
	const connID = "6c1f0e8a-2b7d-4c3e-9f10-8a2b3c4d5e6f"
	block := func(name string, set map[string]attr.Value) map[string]types.Object {
		m := map[string]types.Object{}
		for _, ct := range checkTypes {
			m[ct.block] = types.ObjectNull(ct.attrTypes(true))
			if ct.block != name {
				continue
			}
			attrs := map[string]attr.Value{}
			for n, typ := range ct.attrTypes(true) {
				attrs[n] = nullOf(typ)
			}
			for n, v := range set {
				attrs[n] = v
			}
			m[name] = types.ObjectValueMust(ct.attrTypes(true), attrs)
		}
		return m
	}
	tests := []struct {
		name   string
		conn   types.String
		blocks map[string]types.Object
		want   string
	}{
		{"pgsql without host or connection", types.StringNull(), block("pgsql_query", nil), "Missing required argument"},
		{"pgsql with connection", str(connID).(types.String), block("pgsql_query", map[string]attr.Value{"query": str("SELECT 1")}), ""},
		{"pgsql with unknown connection", types.StringUnknown(), block("pgsql_query", nil), ""},
		{"pgsql host and connection", str(connID).(types.String), block("pgsql_query", map[string]attr.Value{"host": str("db")}), ""},
		{"pgsql user and connection", str(connID).(types.String), block("pgsql_query", map[string]attr.Value{"username": str("u")}), "Conflicting credentials"},
		{"pgsql password and connection", str(connID).(types.String), block("pgsql_query", map[string]attr.Value{"password_wo": str("pw")}), "Conflicting credentials"},
		{"pgsql password version and connection", str(connID).(types.String), block("pgsql_query", map[string]attr.Value{"password_wo_version": num(1)}), ""},
		{"pgsql password and unknown connection", types.StringUnknown(), block("pgsql_query", map[string]attr.Value{"password_wo": str("pw")}), ""},
		{"mysql user and connection", str(connID).(types.String), block("mysql_query", map[string]attr.Value{"username": str("u")}), "Conflicting credentials"},
		{"mongodb without uri", types.StringNull(), block("mongodb", nil), "Missing required argument"},
		{"mongodb uri", types.StringNull(), block("mongodb", map[string]attr.Value{"uri_wo": str("mongodb://h")}), ""},
		{"mongodb connection", str(connID).(types.String), block("mongodb", nil), ""},
		{"mongodb uri and connection", str(connID).(types.String), block("mongodb", map[string]attr.Value{"uri_wo": str("mongodb://h")}), "Conflicting credentials"},
		{"http connection without url", str(connID).(types.String), block("http", nil), ""},
		{"http basic auth and connection", str(connID).(types.String), block("http", map[string]attr.Value{"basic_auth_password_wo": str("pw")}), "Conflicting credentials"},
		{"redis connection", str(connID).(types.String), block("redis", map[string]attr.Value{"host": str("h")}), "Connection not supported"},
		{"tcp connection", str(connID).(types.String), block("tcp", map[string]attr.Value{"host": str("h"), "port": num(1)}), "Connection not supported"},
		{"smtp without port", types.StringNull(), block("smtp", map[string]attr.Value{"host": str("h")}), "Missing required argument"},
		{"websocket url password", types.StringNull(), block("websocket", map[string]attr.Value{"url": str("wss://u:p@h")}), "Password in URL"},
		{"websocket url", types.StringNull(), block("websocket", map[string]attr.Value{"url": str("wss://h/s")}), ""},
		{"redis secret", types.StringNull(), block("redis", map[string]attr.Value{"host": str("h"), "password_wo": str("pw")}), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var diags diag.Diagnostics
			validateCheckConfig(tc.conn, tc.blocks, &diags)
			if tc.want == "" {
				if diags.HasError() {
					t.Fatalf("unexpected error: %v", diags)
				}
				return
			}
			if !diags.HasError() || diags[0].Summary() != tc.want {
				t.Fatalf("want %q, got %v", tc.want, diags)
			}
		})
	}
}
