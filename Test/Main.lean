import Casbin
import Lean
import Test.Extended

open Casbin Lean

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def assertEq [BEq α] [Repr α] (label : String) (actual expected : α) : IO Unit := do
  unless actual == expected do
    throw (IO.userError s!"{label}: expected {repr expected}, got {repr actual}")

private def expectError (label : String) (result : Except String α) : IO Unit :=
  match result with
  | .error _ => pure ()
  | .ok _ => throw (IO.userError s!"{label}: expected an error")

private def basicModel := "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n" ++
  "[policy_effect]\ne = some(where (p.eft == allow))\n" ++
  "[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"

private def rbacModel := basicModel.replace "[policy_effect]" "[role_definition]\ng = _, _\n[policy_effect]" |>.replace
  "r.sub == p.sub" "g(r.sub, p.sub)"

private def regressions : IO Unit := do
  let e ← unwrap (Enforcer.fromText basicModel "p, alice, data1, read\n")
  assertEq "ACL allow" (← unwrap (e.enforce ["alice", "data1", "read"])) true
  assertEq "ACL deny" (← unwrap (e.enforce ["alice", "data1", "write"])) false
  expectError "request arity" (e.enforce ["alice"])
  expectError "policy arity" (Enforcer.fromText basicModel "p, alice\n")
  expectError "unknown policy type" (Enforcer.fromText basicModel "p2, alice, data1, read\n")
  expectError "bad CSV quote" (Enforcer.fromText basicModel "p, \"alice, data1, read\n")
  expectError "unknown function" (Enforcer.fromText (basicModel.replace "m = " "m = missing(p.sub) && ") "")
  expectError "missing variable" (Enforcer.fromText (basicModel.replace "r.sub" "r.missing") "")
  expectError "nonboolean matcher" (Enforcer.fromText (basicModel.replace "r.sub == p.sub && r.obj == p.obj && r.act == p.act" "r.sub") "")
  expectError "unterminated continuation" (Model.parse (basicModel ++ "\\"))
  expectError "malformed matcher" (Expr.parse "true &&")
  expectError "trailing comma" (Expr.parse "keyMatch(r.sub, p.sub,)")
  assertEq "batch decisions" (← unwrap (e.batchEnforce [["alice", "data1", "read"], ["alice", "data1", "write"]])) [true, false]
  let (added, changed) ← unwrap (e.addPolicy ["bob", "data2", "write"])
  assertEq "add result" changed true
  assertEq "immutable original" (e.hasPolicy ["bob", "data2", "write"]) false
  assertEq "added policy decision" (← unwrap (added.enforce ["bob", "data2", "write"])) true
  let (_, duplicate) ← unwrap (added.addPolicy ["bob", "data2", "write"])
  assertEq "duplicate policy" duplicate false
  let (removed, changed) ← unwrap (added.removePolicy ["bob", "data2", "write"])
  assertEq "remove result" changed true
  assertEq "removed decision" (← unwrap (removed.enforce ["bob", "data2", "write"])) false
  let quoted ← unwrap (Enforcer.fromText basicModel "p, \"a,\"\"b\", \"data,1\", read\n")
  assertEq "quoted CSV decision" (← unwrap (quoted.enforce ["a,\"b", "data,1", "read"])) true
  let roundtrip ← unwrap (quoted.loadPolicy (serializePolicy quoted.rules))
  assertEq "CSV roundtrip" roundtrip.rules quoted.rules
  let spaces ← unwrap (Enforcer.fromText basicModel "p, \"\", \" data \" , read\n")
  assertEq "empty quoted field" (← unwrap (spaces.enforce ["", " data ", "read"])) true
  let spacesAgain ← unwrap (spaces.loadPolicy (serializePolicy spaces.rules))
  assertEq "whitespace CSV roundtrip" spacesAgain.rules spaces.rules
  assertEq "empty policy denies" (← unwrap (e.clearPolicy.enforce ["alice", "data1", "read"])) false
  let root ← unwrap (Enforcer.fromText (basicModel.replace "r.act == p.act" "r.act == p.act || r.sub == 'root'") "")
  assertEq "root with empty policy" (← unwrap (root.enforceEx ["root", "x", "write"])) ⟨true, []⟩
  let roles ← unwrap (Enforcer.fromText rbacModel "p, admin, data1, read\ng, alice, user\ng, user, admin\ng, admin, user\n")
  assertEq "transitive role" (← unwrap (roles.enforce ["alice", "data1", "read"])) true
  assertEq "cyclic missing role" (← unwrap (roles.hasLink "alice" "missing")) false
  assertEq "direct roles" (← unwrap (roles.getRolesForUser "alice")) ["user"]
  let (removed, _) ← unwrap (roles.removeGroupingPolicy ["user", "admin"])
  assertEq "role removal applies" (← unwrap (removed.enforce ["alice", "data1", "read"])) false
  let domainModel := rbacModel.replace "sub, obj, act" "sub, dom, obj, act" |>.replace
    "g = _, _" "g = _, _, _" |>.replace "g(r.sub, p.sub)" "g(r.sub, p.sub, r.dom) && r.dom == p.dom"
  let domains ← unwrap (Enforcer.fromText domainModel "p, admin, tenant1, data1, read\ng, alice, admin, tenant1\n")
  assertEq "domain allow" (← unwrap (domains.enforce ["alice", "tenant1", "data1", "read"])) true
  assertEq "domain isolation" (← unwrap (domains.enforce ["alice", "tenant2", "data1", "read"])) false
  expectError "missing role domain" (domains.hasLink "alice" "admin")
  let wildcard ← unwrap (Enforcer.fromText domainModel "p, admin, tenant1, data1, read\ng, alice, admin, tenant*\n")
  assertEq "domain wildcard disabled by default" (← unwrap (wildcard.enforce ["alice", "tenant1", "data1", "read"])) false
  let wildcard ← unwrap (wildcard.addMatchingFunction "g" (fun a b => .ok (keyMatch a b)) true)
  assertEq "domain matcher opt-in" (← unwrap (wildcard.enforce ["alice", "tenant1", "data1", "read"])) true
  let autoDomainModel := domainModel.replace "r.dom == p.dom" "keyMatch(r.dom, p.dom)"
  let automatic ← unwrap (Enforcer.fromText autoDomainModel "p, viewer, tenant*, data1, read\ng, alice, admin, tenant1\ng, admin, viewer, tenant*\n")
  assertEq "automatic domain inheritance" (← unwrap (automatic.enforce ["alice", "tenant1", "data1", "read"])) true
  assertEq "automatic domain isolation" (← unwrap (automatic.enforce ["alice", "other", "data1", "read"])) false
  let names ← unwrap (Enforcer.fromText rbacModel "p, admin, data1, read\ng, user/*, admin\n")
  let names ← unwrap (names.addMatchingFunction "g" (fun a b => .ok (keyMatch a b)))
  assertEq "role name matcher" (← unwrap (names.enforce ["user/alice", "data1", "read"])) true
  for (input, pat, expected) in [("abc", "a(b|c)+", true), ("ab", "^a[0-9]+$", false),
      ("a23", "^a[0-9]+$", true), ("zGETz", "GET|POST", true), ("abc", "^d.*$", false),
      ("", "^(a?)*$", true), ("ac", "^a(b)?c$", true)] do
    assertEq s!"regex {input} {pat}" (← unwrap (regexMatch input pat)) expected
  expectError "invalid regex" (regexMatch "abc" "[")
  assertEq "regex counted quantifier" (← unwrap (regexMatch "aabc" "a{2}")) true
  expectError "regex nested quantifier" (regexMatch "abc" "a**")
  assertEq "keyMatch suffix" (keyMatch "/foo/bar" "/foo/*") true
  assertEq "keyMatch prefix boundary" (keyMatch "/foobar" "/foo/*") false
  assertEq "keyMatch2" (← unwrap (keyMatch2 "/users/123" "/users/:id")) true
  assertEq "keyMatch2 nonempty parameter" (← unwrap (keyMatch2 "/users/" "/users/:id")) false
  assertEq "keyMatch3" (← unwrap (keyMatch3 "/users/123" "/users/{id}")) true
  assertEq "keyMatch5 query" (← unwrap (keyMatch5 "/users/123?q=1" "/users/{id}")) true
  assertEq "glob path separator" (← unwrap (globMatch "/foo/x/y" "/foo/*")) false
  assertEq "glob double star" (← unwrap (globMatch "/foo/x/y" "/foo/**")) true
  assertEq "glob zero directories" (← unwrap (globMatch "/foo/bar" "/foo/**/bar")) true
  assertEq "IPv4 CIDR" (← unwrap (ipMatch "192.168.2.17" "192.168.2.0/24")) true
  assertEq "IPv4 other subnet" (← unwrap (ipMatch "192.168.3.17" "192.168.2.0/24")) false
  assertEq "IPv6 CIDR" (← unwrap (ipMatch "2001:db8::42" "2001:db8::/32")) true
  assertEq "IPv6 canonical equality" (← unwrap (ipMatch "::1" "0:0:0:0:0:0:0:1")) true
  expectError "invalid IP" (ipMatch "bad" "10.0.0.0/8")
  expectError "invalid CIDR" (ipMatch "10.0.0.1" "10.0.0.0/33")
  let customModel := basicModel.replace "r.sub == p.sub" "same(r.sub, p.sub)"
  let custom ← unwrap (Enforcer.fromText customModel "p, alice, data1, read\n"
    [("same", fun args => match args with | [a, b] => .ok (a == b) | _ => .error "arity")])
  assertEq "custom function" (← unwrap (custom.enforce ["alice", "data1", "read"])) true
  let priorityModel := rbacModel.replace "p = sub, obj, act" "p = priority, sub, obj, act, eft" |>.replace
    "some(where (p.eft == allow))" "priority(p.eft) || deny"
  let priorities ← unwrap (Enforcer.fromText priorityModel "p, 10, alice, data1, read, deny\np, 1, alice, data1, read, allow\n")
  assertEq "numeric priority" (← unwrap (priorities.enforceEx ["alice", "data1", "read"]))
    ⟨true, ["1", "alice", "data1", "read", "allow"]⟩
  let nonnumeric ← unwrap (Enforcer.fromText priorityModel "p, bad, alice, data1, read, allow\n")
  assertEq "nonnumeric priority retains decision" (← unwrap (nonnumeric.enforce ["alice", "data1", "read"])) true
  let (priorities, _) ← unwrap (priorities.addPolicy ["-1", "alice", "data1", "read", "deny"])
  assertEq "priority after mutation" (← unwrap (priorities.enforce ["alice", "data1", "read"])) false
  let denyModel := basicModel.replace "p = sub, obj, act" "p = sub, obj, act, eft" |>.replace
    "some(where (p.eft == allow))" "some(where (p.eft == allow)) && !some(where (p.eft == deny))"
  let deny ← unwrap (Enforcer.fromText denyModel "p, alice, data1, read, allow\np, alice, data1, read, deny\n")
  assertEq "deny overrides allow" (← unwrap (deny.enforceEx ["alice", "data1", "read"]))
    ⟨false, ["alice", "data1", "read", "deny"]⟩
  let regexEffectModel := denyModel.replace "r.act == p.act" "regexMatch(r.act, p.act)"
  let fastAllow ← unwrap (Enforcer.fromText regexEffectModel "p, alice, data1, read, allow\np, alice, data1, [, allow\n")
  assertEq "allow+deny with allow-only effects short-circuits" (← unwrap (fastAllow.enforce ["alice", "data1", "read"])) true
  let onlyRequest := denyModel.replace "r.sub == p.sub && r.obj == p.obj && r.act == p.act" "r.sub == 'alice'"
  let direct ← unwrap (Enforcer.fromText onlyRequest "p, bob, data1, read, deny\n")
  assertEq "request-only matcher ignores policy effects" (← unwrap (direct.enforceEx ["alice", "data1", "read"]))
    ⟨true, ["bob", "data1", "read", "deny"]⟩
  let multiModel := basicModel ++ "p2 = invalid\n"
  expectError "definition in wrong section" (Enforcer.fromText multiModel "")
  let namedModel := basicModel.replace "p = sub, obj, act" "p = sub, obj, act\np2 = sub, obj, act" |>.replace
    "e = some(where (p.eft == allow))" "e = some(where (p.eft == allow))\ne2 = some(where (p2.eft == allow))" |>.replace
    "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act" "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\nm2 = r.sub == p2.sub && r.obj == p2.obj && r.act == p2.act"
  let named ← unwrap (Enforcer.fromText namedModel "p, bob, data1, read\np2, alice, data1, read\n")
  assertEq "named policy default isolation" (← unwrap (named.enforce ["alice", "data1", "read"])) false
  assertEq "named policy context" (← unwrap (named.enforce ["alice", "data1", "read"]
    { policyType := "p2", effectType := "e2", matcherType := "m2" })) true
  IO.println "PASS core regressions"

private structure ConformanceTest where
  request : List String
  allow : Bool
  explain : List String
  deriving FromJson

private structure ConformanceCase where
  model : String
  policy : String
  tests : List ConformanceTest
  deriving FromJson

private def unsupported : List (String × String) := []

private def conformance (root : System.FilePath) : IO Unit := do
  let entries ← (root / "cases").readDir
  let paths := entries.toList.map (·.path) |>.filter (fun p => p.extension == some "json")
    |>.mergeSort (fun a b => a.toString ≤ b.toString)
  if paths.isEmpty then throw (IO.userError "no conformance cases found")
  let mut total := 0
  let mut suites := 0
  let mut failures := 0
  let mut skipped := 0
  for path in paths do
    let name := path.fileName.getD ""
    if let some (_, reason) := unsupported.find? (·.1 == name) then
      IO.println s!"SKIP {name}: {reason}"
      skipped := skipped + 1
      continue
    let data : ConformanceCase ← unwrap (fromJson? (← unwrap (Json.parse (← IO.FS.readFile path)) ))
    let e ← Enforcer.fromFiles (root / "data" / data.model) (root / "data" / data.policy)
    let mut caseFailures := 0
    for test in data.tests do
      total := total + 1
      let result := e.enforceEx test.request
      let expected := Decision.mk test.allow test.explain
      match result with
      | .ok actual =>
        if actual != expected then
          caseFailures := caseFailures + 1
          if caseFailures ≤ 3 then IO.println s!"FAIL {name} {repr test.request}: expected {repr expected}, got {repr actual}"
      | .error error =>
        caseFailures := caseFailures + 1
        if caseFailures ≤ 3 then IO.println s!"FAIL {name} {repr test.request}: {error}"
    suites := suites + 1
    failures := failures + caseFailures
    IO.println s!"{if caseFailures == 0 then "PASS" else "FAIL"} {name}: {data.tests.length} requests, {caseFailures} failures"
  IO.println s!"Conformance: {suites} suites, {total} requests, {failures} failures, {skipped} unsupported suites"
  unless failures == 0 do throw (IO.userError "conformance failed")

def main (args : List String) : IO UInt32 := do
  try
    regressions
    Extended.run
    let root := args.head? |>.getD ((← IO.getEnv "CASBIN_CONFORMANCE_DIR").getD "conformance")
    conformance root
    return 0
  catch error =>
    (← IO.getStderr).putStrLn s!"FAIL: {error}"
    return 1
