import Casbin

open Casbin

namespace Extended

private def unwrap (result : Except String α) : IO α :=
  match result with
  | .ok value => pure value
  | .error error => throw (IO.userError error)

private def check [BEq α] [Repr α] (label : String) (actual expected : α) : IO Unit :=
  unless actual == expected do throw (IO.userError s!"{label}: expected {repr expected}, got {repr actual}")

private def failure (label : String) (fn : IO α) : IO Unit := do
  let failed ← try let _ ← fn; pure false catch _ => pure true
  unless failed do throw (IO.userError s!"{label}: expected failure")

private def model := "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n" ++
  "[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"

private def rolesModel := model.replace "[policy_effect]" "[role_definition]\ng = _, _\n[policy_effect]" |>.replace
  "r.sub == p.sub" "g(r.sub, p.sub)"

private def typedAndDynamic : IO Unit := do
  let abac ← unwrap (Enforcer.fromText (model.replace "r.sub == p.sub && r.obj == p.obj && r.act == p.act"
    "r.sub.Age >= 18 && r.obj.Owner == r.sub.Name && r.obj.Price * 2 <= r.sub.Budget") "")
  let adult := Value.object [("Age", .number 25), ("Name", .text "alice"), ("Budget", .number 100)]
  let item := Value.object [("Owner", .text "alice"), ("Price", .number 30)]
  check "object and numeric ABAC" (← unwrap (abac.enforceValues [adult, item, .text "read"])) true
  let minor := Value.object [("Age", .number 17), ("Name", .text "alice"), ("Budget", .number 100)]
  check "numeric ABAC denies minor" (← unwrap (abac.enforceValues [minor, item, .text "read"])) false
  failure "missing object field" (unwrap (abac.enforceValues [.object [], item, .text "read"]))
  let jsonABAC := abac.enableAcceptJsonRequest true
  check "JSON object request" (← unwrap (jsonABAC.enforce [adult.toJson.compress, item.toJson.compress, "read"])) true
  let evalModel := model.replace "p = sub, obj, act" "p = rule, obj, act" |>.replace
    "r.sub == p.sub && r.obj == p.obj && r.act == p.act" "eval(p.rule) && r.obj.Owner == r.sub.Name"
  let dynamic ← unwrap (Enforcer.fromText evalModel "p, r.sub.Age > 18 && r.sub.Budget / 2 >= 30, any, read\n")
  check "dynamic attribute expression" (← unwrap (dynamic.enforceValues [adult, item, .text "read"])) true
  let recursive ← unwrap (Enforcer.fromText evalModel "p, true && eval(p.rule), any, read\n")
  failure "bounded recursive eval" (unwrap (recursive.enforceValues [adult, item, .text "read"]))
  let arithmetic ← unwrap (Enforcer.fromText (model.replace "r.sub == p.sub && r.obj == p.obj && r.act == p.act"
    "(2 + 3 * 4 == 14) && (2 ** 3 == 8) && (true ? 5 : 1 / 0) == 5 && 'x' + 'y' == 'xy'") "")
  check "arithmetic precedence and lazy ternary" (← unwrap (arithmetic.enforce ["a", "b", "c"])) true
  let listModel := model.replace "r.sub == p.sub && r.obj == p.obj && r.act == p.act" "r.act in r.sub.Actions"
  let lists ← unwrap (Enforcer.fromText listModel "")
  check "attribute array membership" (← unwrap (lists.enforceValues [.object [("Actions", .array [.text "read"])], .text "x", .text "read"])) true
  check "keyMatch4 repeated parameter" (← unwrap (keyMatch4 "/a/42/child/42" "/(a|b)/{id}/child/{id}")) true
  check "keyMatch4 repeated parameter mismatch" (← unwrap (keyMatch4 "/a/42/child/43" "/(a|b)/{id}/child/{id}")) false
  check "keyGet" (keyGet "/foo/bar" "/foo/*") "bar"
  check "keyGet2" (← unwrap (keyGet2 "/users/42" "/users/:id" "id")) "42"
  check "keyGet3 capture with embedded group" (← unwrap (keyGet3 "/a/42" "/(a|b)/{id}" "id")) "42"
  check "IPv4 mapped equality" (← unwrap (ipMatch "::ffff:192.168.1.2" "192.168.1.2")) true
  check "IPv4 mapped CIDR" (← unwrap (ipMatch "192.168.1.2" "::ffff:192.168.1.0/120")) true
  IO.println "PASS typed ABAC, dynamic eval, arithmetic, extraction matchers, and mapped IP"

private def conditionsAndManagement : IO Unit := do
  let timedModel := rolesModel.replace "g = _, _" "g = _, _, (_, _)"
  let e ← unwrap (Enforcer.fromText timedModel "p, admin, data1, read\ng, alice, admin, 2026-01-01 00:00:00, 2027-01-01 00:00:00\n")
  let e ← unwrap (e.addTimeCondition "alice" "admin")
  let active := { e with now := "2026-11-05 00:00:00" }
  check "time condition active" (← unwrap (active.enforce ["alice", "data1", "read"])) true
  check "time condition expired" (← unwrap ({ e with now := "2027-01-01 00:00:00" }.enforce ["alice", "data1", "read"])) false
  check "strict start boundary" (← unwrap (timeMatchAt "2026-01-01 00:00:00" "2026-01-01 00:00:00" "_")) false
  failure "invalid date" (unwrap (timeMatchAt "2026-11-05 00:00:00" "2026-02-31 00:00:00" "_"))
  let expired ← unwrap (active.setLinkConditionParams "alice" "admin" ["_", "2025-01-01 00:00:00"])
  check "condition parameters update" (← unwrap (expired.enforce ["alice", "data1", "read"])) false
  let constrainedModel := rolesModel ++ "[constraint_definition]\nc = sod('reader', 'writer')\n"
  let constrained ← unwrap (Enforcer.fromText constrainedModel "g, alice, reader\n")
  failure "constraint on mutation" (unwrap (constrained.addGroupingPolicy ["alice", "writer"]))
  failure "constraint on load" (unwrap (Enforcer.fromText constrainedModel "g, alice, reader\ng, alice, writer\n"))
  let e ← unwrap (Enforcer.fromText rolesModel "p, admin, data1, read\ng, alice, member\ng, member, admin\n")
  check "implicit roles API" (← unwrap (e.getImplicitRolesForUser "alice")) ["member", "admin"]
  check "implicit permissions API" (← unwrap (e.getImplicitPermissionsForUser "alice")) [["admin", "data1", "read"]]
  let (e, _) ← unwrap (e.addPolicies [["bob", "data1", "write"], ["carol", "data2", "read"]])
  check "filtered policies" (← unwrap (e.getFilteredPolicy 1 ["data1"])) [["admin", "data1", "read"], ["bob", "data1", "write"]]
  let (e, _) ← unwrap (e.updatePolicy ["bob", "data1", "write"] ["bob", "data2", "write"])
  check "updated policy effect" (← unwrap (e.enforce ["bob", "data1", "write"])) false
  failure "atomic batch validation" (unwrap (e.addPolicies [["dave", "data1", "write"], ["invalid"]]))
  check "failed batch keeps original" (e.hasPolicy ["dave", "data1", "write"]) false
  let (e, _) ← unwrap (e.deleteRole "admin")
  check "delete role removes permissions and links" (← unwrap (e.enforce ["alice", "data1", "read"])) false
  check "enforcement disabled" (← unwrap ((e.enableEnforce false).enforce [])) true
  IO.println "PASS time conditions, constraints, bulk management, role queries, and disabled enforcement"

private def runtimeAndStorage : IO Unit := do
  let base ← unwrap (Enforcer.fromText model "p, alice, data1, read\n")
  let adapter ← Adapter.memory base.rules
  let runtime ← RuntimeEnforcer.new base (some adapter)
  runtime.enableCache true 60000 2
  check "initial cache decision" (← runtime.enforce ["alice", "data1", "read"]) true
  check "cached result" (← runtime.enforce ["alice", "data1", "read"]) true
  check "one cache entry" (← runtime.state.atomically do return (← get).cache.length) 1
  runtime.enableCache true 5 2
  let _ ← runtime.enforce ["alice", "data1", "read"]
  let expiry ← runtime.state.atomically do return (← get).cache.head?.map (·.expiry)
  check "cache entry has an expiry" expiry.isSome true
  IO.sleep 10
  let _ ← runtime.enforce ["alice", "data1", "read"]
  let refreshed ← runtime.state.atomically do return (← get).cache.head?.map (·.expiry)
  check "refreshed cache entry has an expiry" refreshed.isSome true
  check "expired cache entry is recomputed" (decide (refreshed.getD 0 > expiry.getD 0)) true
  let events ← IO.mkRef (0 : Nat)
  runtime.setWatcher (fun _ => events.modify (· + 1))
  let _ ← runtime.removePolicy ["alice", "data1", "read"]
  check "cache invalidated after mutation" (← runtime.enforce ["alice", "data1", "read"]) false
  check "watcher invoked" (← events.get) 1
  check "autosave persisted" (← adapter.load base.model) []
  let tasks ← (List.range 30).mapM fun index => IO.asTask do
    let _ ← runtime.addPolicy ["user" ++ toString index, "data1", "read"]
    pure ()
  for task in tasks do
    match task.get with
    | .ok _ => pure ()
    | .error error => throw error
  check "concurrent updates preserved" (← runtime.snapshot).rules.length 30
  let tx ← runtime.beginTransaction
  let _ ← tx.mutate (fun e => e.addPolicy ["alice", "data1", "read"])
  check "transaction sees buffered rule" (← tx.enforceEx ["alice", "data1", "read"]).allow true
  check "uncommitted transaction isolation" (← runtime.enforce ["alice", "data1", "read"]) false
  tx.commit
  check "commit publishes rule" (← runtime.enforce ["alice", "data1", "read"]) true
  let stale ← runtime.beginTransaction
  let _ ← stale.mutate (fun e => e.addPolicy ["stale", "data1", "read"])
  let _ ← runtime.addPolicy ["newer", "data1", "read"]
  stale.commit
  check "disjoint transaction merges" (← runtime.enforce ["stale", "data1", "read"]) true
  check "disjoint transaction preserves concurrent write" (← runtime.enforce ["newer", "data1", "read"]) true
  let conflict ← runtime.beginTransaction
  let _ ← conflict.mutate (fun e => e.removePolicy ["newer", "data1", "read"])
  let _ ← runtime.removePolicy ["newer", "data1", "read"]
  failure "overlapping transaction conflict" conflict.commit
  conflict.rollback
  let broken : Adapter := { load := fun _ => pure base.rules, save := fun _ _ => throw (IO.userError "save failed"), supportsIncremental := true }
  let failed ← RuntimeEnforcer.new base (some broken)
  failure "storage failure" (failed.addPolicy ["bob", "data1", "read"])
  check "save failure preserves memory" (← failed.enforce ["bob", "data1", "read"]) false
  runtime.setWatcher (fun _ => throw (IO.userError "notification failed"))
  failure "watcher failure is reported" (runtime.addPolicy ["watcher", "data1", "read"])
  check "watcher failure occurs after commit" (← runtime.enforce ["watcher", "data1", "read"]) true
  let replica ← RuntimeEnforcer.new base
  let notifyCount ← IO.mkRef (0 : Nat)
  replica.setWatcher (fun _ => notifyCount.modify (· + 1))
  runtime.setWatcher (fun _ => pure ())
  runtime.setDispatcher (fun event => replica.applyRemote event.after)
  let _ ← runtime.addPolicy ["replicated", "data1", "read"]
  check "dispatcher replicates committed policy" (← replica.enforce ["replicated", "data1", "read"]) true
  check "replication does not loop notifications" (← notifyCount.get) 0
  let directory : System.FilePath := "/tmp/casbin-lean4-test-" ++ toString (← IO.monoNanosNow)
  IO.FS.createDirAll directory
  try
    let file := directory / "policy.csv"
    let disk := Adapter.file file
    disk.save base.model base.rules
    check "file roundtrip" (← disk.load base.model) base.rules
    let sqlite := Adapter.sqlite (directory / "policy.db")
    sqlite.save base.model base.rules
    check "SQLite roundtrip" (← sqlite.load base.model) base.rules
    let first ← RuntimeEnforcer.new base (some sqlite)
    let second ← RuntimeEnforcer.new base (some sqlite)
    let _ ← first.addPolicy ["first; 'quoted'", "data1", "read"]
    let _ ← second.addPolicy ["second", "data1", "read"]
    let shared ← sqlite.load base.model
    check "SQLite incremental preserves other enforcer writes" shared.length (base.rules.length + 2)
    check "SQLite preserves SQL punctuation as data" (shared.contains ⟨"p", ["first; 'quoted'", "data1", "read"]⟩) true
    let constrainedModel := rolesModel ++ "[constraint_definition]\nc = sod('reader', 'writer')\n"
    let constrained ← unwrap (Enforcer.fromText constrainedModel "")
    let storage := Adapter.sqlite (directory / "constraints.db")
    storage.save constrained.model []
    let reader ← RuntimeEnforcer.new constrained (some storage)
    let writer ← RuntimeEnforcer.new constrained (some storage)
    let _ ← reader.addGroupingPolicy ["alice", "reader"]
    failure "shared SQLite constraint checked on merged state" (writer.addGroupingPolicy ["alice", "writer"])
    check "SQLite failed constraint leaves persisted state intact" (← storage.load constrained.model) [⟨"g", ["alice", "reader"]⟩]
    let text ← Adapter.string (serializePolicy base.rules)
    check "string adapter roundtrip" (← text.load base.model) base.rules
    let filtered ← RuntimeEnforcer.new base (some adapter)
    filtered.loadPolicy (some { p := ["alice"] })
    check "filtered flag" (← filtered.isFiltered) true
    failure "filtered save prohibited" filtered.savePolicy
  finally
    for entry in ← directory.readDir do IO.FS.removeFile entry.path
    IO.FS.removeDir directory
  IO.println "PASS cache invalidation, concurrent updates, persistence, transactions, and replication"

private def operators : IO Unit := do
  let e ← unwrap (Enforcer.fromText model "")
  let rows ← unwrap ((← unwrap (Lean.Json.parse (← IO.FS.readFile "Test/data/builtin.json"))).getArr?)
  let mut failures := []
  for row in rows do
    let name ← unwrap (row.getObjValAs? String "name")
    let args ← unwrap (row.getObjValAs? (List Value) "args")
    let source := name ++ "(" ++ String.intercalate "," (args.map (fun value => value.toJson.compress)) ++ ")"
    let legacy := (row.getObjValAs? Bool "legacy").toOption.getD false
    let result := if legacy then e.evaluateLegacyBuiltin name args else e.evaluateExpression source
    match row.getObjVal? "expected", result with
    | .ok json, .ok actual =>
      let expected ← unwrap (Value.fromJson json)
      if actual != expected then failures := failures ++ [s!"{source}: expected {repr expected}, got {repr actual}"]
    | .error _, .error _ => pure ()
    | .error _, .ok _ => failures := failures ++ [s!"{source}: expected an argument or pattern error"]
    | .ok _, .error error => failures := failures ++ [s!"{source}: {error}"]
  for error in failures do IO.println s!"FAIL builtin: {error}"
  check "upstream builtin failures" failures.length 0
  let arithmetic ← unwrap ((← unwrap (Lean.Json.parse (← IO.FS.readFile "Test/data/arithmetic.json"))).getArr?)
  for row in arithmetic do
    let source ← unwrap (row.getObjValAs? String "expression")
    if let .ok expected := row.getObjVal? "expected" then
      check s!"Go arithmetic: {source}" (← unwrap (e.evaluateExpression source)) (← unwrap (Value.fromJson expected))
    else failure s!"Go invalid expression: {source}" (unwrap (e.evaluateExpression source))
  for (input, pattern, expected) in [
    ("aaab", "a{2,3}?b", true), ("你好", "^\\p{Han}+$", true),
    ("HELLO", "(?i)^hello$", true), ("a\nb", "(?s)^a.b$", true),
    ("x\ny\nz", "(?m)^y$", true), ("cat!", "\\bcat\\b", true),
    ("cat1", "\\bcat\\b", false), ("123", "^[\\d]+$", true),
    ("é", "^\\w$", false), ("abc", "^[[:alpha:]]+$", true)] do
    check "complete regex" (← unwrap (regexMatch input pattern)) expected
  failure "RE2 rejects lookahead" (unwrap (regexMatch "a" "a(?=b)"))
  failure "RE2 rejects backreferences" (unwrap (regexMatch "aa" "(a)\\1"))
  check "glob nested alternatives" (← unwrap (globMatch "/a/x.json" "/{a,{b,c}}/*.{json,txt}")) true
  IO.println s!"PASS {rows.size} upstream builtin cases, {arithmetic.size} Go expression cases, and full RE2 syntax"

private def operational : IO Unit := do
  let config ← unwrap (Config.parse "enabled = true\n[server]\nport = 8080\nratio = 0.5\n")
  check "typed config boolean" (← unwrap (config.bool "enabled")) true
  check "typed config integer" (← unwrap (config.int "server::port")) 8080
  check "typed config float" (← unwrap (config.float64 "server::ratio")) (0.5 : Float)
  let base ← unwrap (Enforcer.fromText rolesModel "p, admin, data1, read\ng, alice, admin\n")
  let manager : RoleManager := {
    hasLink := fun rules user role _ => pure (rules.any fun r => r.values == [user, role])
    getRoles := fun rules user _ => pure ((rules.filter (fun r => r.values[0]? == some user)).filterMap (·.values[1]?))
    getUsers := fun rules role _ => pure ((rules.filter (fun r => r.values[1]? == some role)).filterMap (·.values[0]?))
  }
  let custom ← unwrap (base.setRoleManager manager)
  check "custom role manager" (← unwrap (custom.enforce ["alice", "data1", "read"])) true
  let effector : Effector := fun _ entries =>
    pure ⟨entries.any (fun (_, score, _) => score == 2), []⟩
  let scored := base.setEffector effector
  check "custom effector receives numeric scores" (← unwrap (scored.enforceWithMatcher "2" [.text "a", .text "b", .text "c"])).allow true
  let customEffect := rolesModel.replace "some(where (p.eft == allow))" "custom(p.eft)"
  let configured ← unwrap (Enforcer.fromText customEffect "" [] [] (some effector))
  check "custom effect expression" (← unwrap (configured.enforceWithMatcher "2" [.text "a", .text "b", .text "c"])).allow true
  let frozen := base.enableAutoBuildRoleLinks false
  let (updated, _) ← unwrap (frozen.addGroupingPolicy ["bob", "admin"])
  check "disabled automatic role building" (← unwrap (updated.enforce ["bob", "data1", "read"])) false
  check "explicit role rebuilding" (← unwrap (updated.buildRoleLinks.enforce ["bob", "data1", "read"])) true
  let roundtrip ← unwrap (Enforcer.fromText base.model.toText (serializePolicy base.rules))
  check "model serialization" (← unwrap (roundtrip.enforce ["alice", "data1", "read"])) true
  unwrap base.detectCycles
  let (cyclic, _) ← unwrap (base.addGroupingPolicy ["admin", "alice"])
  failure "cycle detector" (unwrap cyclic.detectCycles)
  let noPolicy := model.replace "[policy_definition]\np = sub, obj, act\n" "" |>.replace
    "r.sub == p.sub && r.obj == p.obj && r.act == p.act" "r.sub.Age >= 18"
  let abac ← unwrap (Enforcer.fromText noPolicy "")
  check "model without policies" (← unwrap (abac.enforceValues [.object [("Age", .number 21)], .text "x", .text "r"])) true
  let exported ← unwrap (Lean.Json.parse (base.casbinJsGetPermissionForUser "alice"))
  check "Casbin.js retains grouping records" (← unwrap (exported.getObjValAs? (List (List String)) "g")) [["g", "alice", "admin"]]
  let result ← base.explain [.text "alice", .text "data1", .text "read"] { endpoint := "mock://test", model := "mock" }
    (fun config request => do
      check "AI model" config.model "mock"
      let messages ← unwrap (request.getObjVal? "messages" >>= Lean.Json.getArr?)
      check "AI message count" messages.size 2
      return Lean.Json.mkObj [("choices", .arr #[Lean.Json.mkObj [("message", Lean.Json.mkObj [("content", .str "Alice inherits admin.")])]])])
  check "AI mock explanation" result "Alice inherits admin."
  let calls ← IO.mkRef (0 : Nat)
  let poolRef ← IO.mkRef (none : Option EnforcerPool)
  let pool ← EnforcerPool.new (fun _ _ => do
    calls.modify (· + 1)
    if (← calls.get) == 1 then
      if let some pool ← poolRef.get then pool.invalidateAll
    RuntimeEnforcer.new base) 2
  poolRef.set (some pool)
  let _ ← pool.get "a"
  check "pool invalidation during factory retries" (← calls.get) 2
  let _ ← pool.get "a"
  check "pool cache hit" (← calls.get) 2
  let _ ← pool.get "b"
  let _ ← pool.get "c"
  check "pool bounded capacity" (← pool.size) 2
  let _ ← pool.get "a"
  check "pool evicts oldest" (← calls.get) 5
  let adapter ← Adapter.memory base.rules
  let runtime ← RuntimeEnforcer.new base (some adapter)
  let txA ← runtime.beginTransaction
  let txB ← runtime.beginTransaction
  let idA ← txA.id
  check "unique transaction IDs" (idA != (← txB.id)) true
  check "active transaction lookup" (← runtime.isTransactionActive idA) true
  txA.rollback
  txB.rollback
  check "closed transaction removed from registry" (← runtime.isTransactionActive idA) false
  let logCalls ← IO.mkRef (0 : Nat)
  runtime.setLogger (fun _ _ => do let _ ← runtime.snapshot; logCalls.modify (· + 1))
  let _ ← runtime.enforce ["alice", "data1", "read"]
  check "normal execution logs outside mutex" (← logCalls.get) 1
  let replica ← RuntimeEnforcer.new base
  let _ ← replica.applyRemoteVersioned "primary" 2 []
  check "out-of-order snapshots rejected" (← replica.applyRemoteVersioned "primary" 1 base.rules) false
  check "old snapshot does not restore revoked access" (← replica.enforce ["alice", "data1", "read"]) false
  let loader ← runtime.startAutoLoadPolicy 10
  failure "duplicate autoload" (runtime.startAutoLoadPolicy 10)
  adapter.save base.model []
  let deadline := (← IO.monoMsNow) + 3000
  while ← runtime.enforce ["alice", "data1", "read"] do
    if (← IO.monoMsNow) > deadline then throw (IO.userError "autoload did not refresh policy")
    IO.sleep 10
  loader.stop
  check "autoload stopped" (← runtime.isAutoLoadingRunning) false
  let writes ← IO.mkRef (0 : Nat)
  let ctxAdapter : ContextAdapter := {
    load := fun ctx _ => do ctx.check; pure base.rules
    save := fun ctx _ _ => do ctx.check; writes.modify (· + 1)
  }
  let contextual ← ContextEnforcer.new base ctxAdapter
  let cancelled ← OperationContext.new
  cancelled.cancel
  failure "cancelled load" (contextual.loadPolicy cancelled)
  failure "cancelled write" (contextual.mutate cancelled (fun e => e.addPolicy ["bob", "data1", "read"]))
  check "cancelled write never reaches adapter" (← writes.get) 0
  let expired ← OperationContext.new (some 0)
  failure "expired context" (contextual.enforce expired [.text "alice", .text "data1", .text "read"])
  let active ← OperationContext.new
  let _ ← contextual.mutate active (fun e => e.addPolicy ["bob", "data1", "read"])
  check "context persistence" (← writes.get) 1
  let started ← IO.mkRef false
  let cooperative ← ContextEnforcer.new base {
    load := fun ctx _ => do
      started.set true
      while !(← ctx.cancelled.get) do IO.sleep 5
      ctx.check
      pure []
    save := fun ctx _ _ => ctx.check
  }
  let token ← OperationContext.new
  let loading ← IO.asTask (cooperative.loadPolicy token)
  while !(← started.get) do IO.sleep 5
  token.cancel
  failure "cancellation during adapter IO" (IO.ofExcept loading.get)
  check "cancelled load preserves snapshot" (← cooperative.runtime.snapshot).rules base.rules
  IO.println "PASS custom managers/effectors, cycle detection, frontend, AI mock, pool, autoload, and cancellation"

def run : IO Unit := do
  typedAndDynamic
  conditionsAndManagement
  runtimeAndStorage
  operators
  operational

end Extended
